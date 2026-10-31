const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const Razorpay = require("razorpay");
const dotenv = require("dotenv");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { rateLimit } = require("express-rate-limit");
const nodemailer = require("nodemailer");

dotenv.config();

const { requireAdmin, requireCustomer } = require("./auth");
const randomUUID = () => crypto.randomUUID();


// Optional Gmail SMTP notifications. Email failures never undo a verified payment.
const mailTransport = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    })
    : null;

function getCustomerEmailForOrder(orderId) {
    return db.prepare(`
        SELECT c.email, c.name, o.id AS order_id, o.document_name,
               o.total_amount_paise, o.advance_amount_paise,
               o.balance_amount_paise, o.payment_status, o.created_at
        FROM orders o JOIN customers c ON c.id = o.customer_id
        WHERE o.id = ?
    `).get(orderId);
}

async function sendOrderNotification(orderId, notificationType, options = {}) {
    const order = getCustomerEmailForOrder(orderId);
    if (!order || !order.email) return { sent: false, reason: "no_email" };
    if (!mailTransport || !process.env.EMAIL_FROM) {
        console.error("Email notification skipped: SMTP settings are incomplete.");
        return { sent: false, reason: "smtp_not_configured" };
    }

    // One row per order/type is maintained by the existing database schema.
    const existing = db.prepare(`
        SELECT id, notification_status FROM email_notifications
        WHERE order_id = ? AND notification_type = ?
    `).get(orderId, notificationType);
    if (existing && existing.notification_status === "sent" && !options.allowResend) {
        return { sent: true, alreadySent: true };
    }

    db.prepare(`
        INSERT INTO email_notifications
            (order_id, notification_type, recipient_email, notification_status, attempts, last_error, updated_at)
        VALUES (?, ?, ?, 'pending', 0, '', datetime('now'))
        ON CONFLICT(order_id, notification_type) DO UPDATE SET
            recipient_email = excluded.recipient_email,
            notification_status = 'pending',
            last_error = '',
            updated_at = datetime('now')
    `).run(orderId, notificationType, order.email);

    const money = paise => `₹${(Number(paise || 0) / 100).toFixed(2)}`;
    const isDelivery = notificationType === "delivery_confirmation";
    const subject = isDelivery
        ? `GoPrint order #${orderId} is completed`
        : `GoPrint payment receipt — order #${orderId}`;
        const text = isDelivery
        ? `Hello ${order.name},\n\nYour GoPrint order #${orderId} (${order.document_name}) has been marked completed.\nCustomer Email: ${order.email}\nTotal: ${money(order.total_amount_paise)}\nPayment status: ${order.payment_status}\n\nThank you for using GoPrint.`
        : `Hello ${order.name},\n\nThis is your GoPrint ${options.paymentType === "balance" ? "balance payment" : "advance payment"} receipt.\nOrder: #${orderId}\nCustomer Email: ${order.email}\nDocument: ${order.document_name}\nPayment received: ${money(options.amountPaise)}\nOrder total: ${money(order.total_amount_paise)}\nBalance remaining: ${money(order.balance_amount_paise)}\nPayment ID: ${options.paymentId || "See your GoPrint order history"}\n\nThank you for using GoPrint.`;
    try {
        await mailTransport.sendMail({
            from: process.env.EMAIL_FROM,
            to: order.email,
            subject,
            text
        });
        db.prepare(`UPDATE email_notifications SET notification_status='sent', attempts=attempts+1, last_error='', updated_at=datetime('now') WHERE order_id=? AND notification_type=?`).run(orderId, notificationType);
        return { sent: true };
    } catch (error) {
        db.prepare(`UPDATE email_notifications SET notification_status='failed', attempts=attempts+1, last_error=?, updated_at=datetime('now') WHERE order_id=? AND notification_type=?`).run(String(error.message || "Email send failed").slice(0, 500), orderId, notificationType);
        console.error(`GoPrint email notification failed (${notificationType}, order ${orderId}):`, error.message);
        return { sent: false, reason: "send_failed" };
    }
}

const db = require("./database");

const app = express();
app.use(
    "/dashboard",
    express.static(path.join(__dirname, "admin"))
);

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const uploadDirectory = path.join(__dirname, "private_uploads");

// Create the private folder automatically if it doesn't exist.
fs.mkdirSync(uploadDirectory, { recursive: true });

const storage = multer.diskStorage({
destination: (req, file, callback) => {
callback(null, uploadDirectory);
},

filename: (req, file, callback) => {
    callback(null, randomUUID() + ".pdf");
}

});

const pdfUpload = multer({
storage: storage,
limits: {
fileSize: 2000 * 1024 * 1024
},
fileFilter: (req, file, callback) => {
const isPdf =
file.mimetype === "application/pdf" &&
path.extname(file.originalname).toLowerCase() === ".pdf";

    if (!isPdf) {
        return callback(new Error("Only PDF files are allowed"));
    }

    callback(null, true);
}

});


const razorpayKeyId = process.env.RAZORPAY_KEY_ID;
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET;

if (!razorpayKeyId || !razorpayKeySecret) {
    console.error("Missing Razorpay credentials in .env file.");
    process.exit(1);
}

const razorpay = new Razorpay({
    key_id: razorpayKeyId,
    key_secret: razorpayKeySecret
});

// Limit repeated customer authentication attempts
const customerAuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many attempts. Please try again in 5 minutes."
    }
});

// Limit repeated admin login attempts
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many login attempts. Please try again later in 1 minutes."
    }
});

// Private admin login
app.post("/admin/login", adminLoginLimiter, async (req, res) => {
    try {
        const { adminId, password } = req.body;

        if (
            typeof adminId !== "string" ||
            typeof password !== "string" ||
            !process.env.ADMIN_ID ||
            !process.env.ADMIN_PASSWORD_HASH ||
            !process.env.JWT_SECRET ||
            process.env.ADMIN_PASSWORD_HASH === "TEMPORARY_PLACEHOLDER" ||
            process.env.JWT_SECRET === "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
        ) {
            return res.status(401).json({
                error: "Invalid credentials or login configuration"
            });
        }

        const validAdminId =
            adminId === process.env.ADMIN_ID;

        const validPassword = await bcrypt.compare(
            password,
            process.env.ADMIN_PASSWORD_HASH
        );

        if (!validAdminId || !validPassword) {
            return res.status(401).json({
                error: "Invalid Admin ID or password"
            });
        }

        const token = jwt.sign(
            {
                role: "admin",
                adminId: process.env.ADMIN_ID
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "30m",
                issuer: "goprint-backend",
                audience: "goprint-admin"
            }
        );

        return res.json({
            success: true,
            message: "Admin login successful",
            token: token,
            expiresIn: 1800
        });

    } catch (error) {
        console.error("Admin login failed:", error.message);

        return res.status(500).json({
            error: "Could not process admin login"
        });
    }
});

// Admin-only endpoint: view all customer orders
app.get("/admin/orders", requireAdmin, (req, res) => {
    try {
        // Fetch all orders, newest first.
        const orders = db.prepare(`
            SELECT *
            FROM orders
            ORDER BY created_at DESC, id DESC
        `).all();

        // Fetch every PDF attached to each order.
        const getDocuments = db.prepare(`
            SELECT *
            FROM order_documents
            WHERE order_id = ?
            ORDER BY document_index ASC, id ASC
        `);

        const result = orders.map((order) => {
            const documents = getDocuments.all(order.id);

            // Support older orders that only have orders.pdf_file_path.
            const allDocuments = documents.length > 0
                ? documents.map((document) => ({
                    ...document,
                    has_pdf: Boolean(document.pdf_file_path),
                    document_name:
                        document.document_name ||
                        document.file_name ||
                        document.original_name ||
                        `Document ${document.document_index || ""}`.trim()
                }))
                : (
                    order.pdf_file_path
                        ? [{
                            id: null,
                            order_id: order.id,
                            document_index: 1,
                            document_name:
                                order.document_name || "Uploaded PDF",
                            pdf_file_path: order.pdf_file_path,
                            has_pdf: true,
                            copies: order.copies,
                            page_count: order.page_count,
                            color_mode: order.color_mode,
                            print_sides: order.print_sides,
                            pages_per_sheet: order.pages_per_sheet,
                            orientation: order.orientation,
                            colour_pages: order.colour_pages
                        }]
                        : []
                );

            return {
                ...order,
                documents: allDocuments,
                documentCount: allDocuments.length,
                has_pdf: allDocuments.some((document) => document.has_pdf)
            };
        });

        res.json({
            success: true,
            orders: result
        });
    } catch (error) {
        console.error("Admin order history error:", error);
        res.status(500).json({
            success: false,
            message: "Could not load admin order history."
        });
    }
});


// Admin-only endpoint: view order details and payment receipt information
app.get("/admin/orders/:id/details", requireAdmin, (req, res) => {
    try {
        const orderId = Number(req.params.id);

        if (!Number.isSafeInteger(orderId) || orderId < 1) {
            return res.status(400).json({
                success: false,
                error: "Invalid order ID"
            });
        }

        // Retrieve complete order and customer information.
        const order = db.prepare(`
            SELECT
                id,
                customer_id,
                customer_name,
                customer_phone,
                (SELECT email FROM customers WHERE customers.id = orders.customer_id) AS customer_email,
                document_name,
                copies,
                color_mode,
                paper_size,
                print_sides,
                page_count,
                pages_per_sheet,
                orientation,
                colour_pages,
                total_amount_paise,
                advance_percentage,
                advance_amount_paise,
                balance_amount_paise,
                payment_status,
                status,
                print_status,
                collection_method,
                collection_location,
                college_year,
                college_department,
                college_section,
                roll_number,
                created_at,
                razorpay_payment_id,
                CASE
                    WHEN pdf_file_path IS NOT NULL
                     AND pdf_file_path != ''
                    THEN 1
                    ELSE 0
                END AS has_pdf
            FROM orders
            WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                success: false,
                error: "Order not found"
            });
        }

        // Retrieve payment history for this order.
        const payments = db.prepare(`
            SELECT
                id,
                amount_paise,
                payment_method,
                payment_type,
                payment_status,
                razorpay_order_id,
                razorpay_payment_id,
                recorded_by,
                created_at
            FROM payments
            WHERE order_id = ?
              AND payment_status = 'paid'
            ORDER BY created_at ASC, id ASC
        `).all(orderId);

        // Support older orders without an advance payment history record.
        const hasAdvanceRecord = payments.some(
            payment => payment.payment_type === "advance"
        );

        let receiptPayments = payments;

        if (
            !hasAdvanceRecord &&
            order.razorpay_payment_id &&
            Number(order.advance_amount_paise) > 0
        ) {
            receiptPayments = [
                {
                    id: null,
                    amount_paise: order.advance_amount_paise,
                    payment_method: "razorpay",
                    payment_type: "advance",
                    payment_status: "paid",
                    razorpay_order_id: null,
                    razorpay_payment_id: order.razorpay_payment_id,
                    recorded_by: "",
                    created_at: order.created_at,
                    legacy_record: true
                },
                ...payments
            ];
        }

        const totalPaidPaise = receiptPayments.reduce(
            (sum, payment) => sum + Number(payment.amount_paise),
            0
        );


// Retrieve every document and its individual print settings.
const documents = db.prepare(`
    SELECT
        id,
        order_id,
        document_index,
        document_name,
        page_count,
        copies,
        color_mode,
        paper_size,
        print_sides,
        pages_per_sheet,
        orientation,
        colour_pages,
        CASE
            WHEN pdf_file_path IS NOT NULL
             AND pdf_file_path != ''
            THEN 1
            ELSE 0
        END AS has_pdf
    FROM order_documents
    WHERE order_id = ?
    ORDER BY document_index ASC, id ASC
`).all(orderId);

// Support older orders that store the PDF directly in orders.
let allDocuments = documents;

if (allDocuments.length === 0 && order.pdf_file_path) {
    allDocuments = [{
        id: null,
        order_id: order.id,
        document_index: 1,
        document_name: order.document_name || "Uploaded PDF",
        page_count: order.page_count,
        copies: order.copies,
        color_mode: order.color_mode,
        paper_size: order.paper_size,
        print_sides: order.print_sides,
        pages_per_sheet: order.pages_per_sheet,
        orientation: order.orientation,
        colour_pages: order.colour_pages,
        amount_paise: order.amount_paise,
        has_pdf: order.has_pdf
    }];
}

order.documents = allDocuments;
order.documentCount = allDocuments.length;

        return res.json({
            success: true,
            order: order,
            receipt: {
                order_id: order.id,
                customer_name: order.customer_name,
                customer_phone: order.customer_phone,
                document_name: order.document_name,
                total_amount_paise: order.total_amount_paise,
                advance_amount_paise: order.advance_amount_paise,
                balance_amount_paise: order.balance_amount_paise,
                payment_status: order.payment_status,
                order_date: order.created_at,
                total_paid_paise: totalPaidPaise,
                payments: receiptPayments
            }
        });

    } catch (error) {
        console.error(
            "Admin order details retrieval failed:",
            error.message
        );

        return res.status(500).json({
            success: false,
            error: "Could not retrieve order details"
        });
    }
});

// Admin-only endpoint: record a cash balance payment
app.post("/admin/orders/:id/collect-cash", requireAdmin, (req, res) => {
    try {
        const orderId = Number(req.params.id);
        const { amountPaise } = req.body;

        if (!Number.isSafeInteger(orderId) || orderId < 1) {
            return res.status(400).json({
                error: "Invalid order ID"
            });
        }

        if (
            !Number.isSafeInteger(amountPaise) ||
            amountPaise <= 0
        ) {
            return res.status(400).json({
                error: "Enter a valid cash payment amount in paise"
            });
        }

        const collectCash = db.transaction(() => {
            const order = db.prepare(`
                SELECT
                    id,
                    total_amount_paise,
                    payment_status,
                    balance_amount_paise
                FROM orders
                WHERE id = ?
            `).get(orderId);

            if (!order) {
                throw new Error("ORDER_NOT_FOUND");
            }

            if (
                !["advance_paid", "paid"].includes(order.payment_status)
            ) {
                throw new Error("ADVANCE_PAYMENT_REQUIRED");
            }

            const payments = db.prepare(`
    SELECT COALESCE(SUM(amount_paise), 0) AS total_paid
    FROM payments
    WHERE order_id = ?
      AND payment_status = 'paid'
`).get(orderId);

const recordedPaid = Number(payments.total_paid);

const verifiedAdvance =
    order.payment_status === "advance_paid" ||
    order.payment_status === "paid"
        ? Number(
            db.prepare(`
                SELECT advance_amount_paise
                FROM orders
                WHERE id = ?
            `).get(orderId)?.advance_amount_paise || 0
        )
        : 0;

const totalPaid = Math.max(recordedPaid, verifiedAdvance);
const orderTotal = Number(order.total_amount_paise);

            if (
                !Number.isSafeInteger(totalPaid) ||
                !Number.isSafeInteger(orderTotal) ||
                orderTotal <= 0
            ) {
                throw new Error("INVALID_PAYMENT_TOTAL");
            }

            const balanceDue = orderTotal - totalPaid;

            if (balanceDue <= 0) {
                throw new Error("NO_BALANCE_DUE");
            }

            if (amountPaise > balanceDue) {
                throw new Error("PAYMENT_EXCEEDS_BALANCE");
            }

            db.prepare(`
                INSERT INTO payments (
                    order_id,
                    amount_paise,
                    payment_method,
                    payment_type,
                    payment_status,
                    recorded_by
                )
                VALUES (?, ?, 'cash', 'balance', 'paid', ?)
            `).run(
                orderId,
                amountPaise,
                req.admin?.adminId || "admin"
            );

            const updatedPayments = db.prepare(`
    SELECT COALESCE(SUM(amount_paise), 0) AS total_paid
    FROM payments
    WHERE order_id = ?
      AND payment_status = 'paid'
`).get(orderId);

const totalPaidAfterCash = Math.max(
    Number(updatedPayments.total_paid),
    verifiedAdvance
);

const remainingBalance = orderTotal - totalPaidAfterCash;

            const newPaymentStatus =
                remainingBalance === 0 ? "paid" : "advance_paid";

            db.prepare(`
                UPDATE orders
                SET balance_amount_paise = ?,
                    payment_status = ?
                WHERE id = ?
            `).run(
                Math.max(0, remainingBalance),
                newPaymentStatus,
                orderId
            );

            return {
    totalPaid: totalPaidAfterCash,
    balanceDue: Math.max(0, remainingBalance),
    paymentStatus: newPaymentStatus
};
        });

        const result = collectCash();

        return res.json({
            success: true,
            message: "Cash payment recorded successfully",
            orderId: orderId,
            totalPaidPaise: result.totalPaid,
            balanceDuePaise: result.balanceDue,
            paymentStatus: result.paymentStatus
        });

    } catch (error) {
        if (error.message === "ORDER_NOT_FOUND") {
            return res.status(404).json({
                error: "Order not found"
            });
        }

        if (error.message === "ADVANCE_PAYMENT_REQUIRED") {
            return res.status(400).json({
                error: "The online advance payment must be verified first"
            });
        }

        if (error.message === "NO_BALANCE_DUE") {
            return res.status(400).json({
                error: "This order has no outstanding balance"
            });
        }

        if (error.message === "PAYMENT_EXCEEDS_BALANCE") {
            return res.status(400).json({
                error: "Cash amount cannot exceed the outstanding balance"
            });
        }

        if (error.message === "INVALID_PAYMENT_TOTAL") {
            return res.status(400).json({
                error: "Invalid order payment totals"
            });
        }

        console.error(
            "Cash collection failed:",
            error.message
        );

        return res.status(500).json({
            error: "Could not record cash payment"
        });
    }
});

// Admin-only endpoint: update an order's status
app.patch("/admin/orders/:id/status", requireAdmin, async (req, res) => {
    try {
        const orderId = Number(req.params.id);
        const { status } = req.body;

        const allowedStatuses = [
            "pending",
            "confirmed",
            "printing",
            "ready_for_collection",
            "completed",
            "cancelled"
        ];

        if (
            !Number.isSafeInteger(orderId) ||
            orderId < 1
        ) {
            return res.status(400).json({
                error: "Invalid order ID"
            });
        }

        if (
            typeof status !== "string" ||
            !allowedStatuses.includes(status)
        ) {
            return res.status(400).json({
                error: "Invalid order status"
            });
        }

                // Check that the order exists and retrieve its payment details.
        const order = db.prepare(`
            SELECT id, total_amount_paise, balance_amount_paise, payment_status, status
            FROM orders WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                error: "Order not found"
            });
        }

        // Prevent completion until the full payment is received.
        if (status === "completed") {
            const total = Number(order.total_amount_paise);
            const storedBalance = Number(order.balance_amount_paise);

            if (
                !Number.isSafeInteger(total) ||
                !Number.isSafeInteger(storedBalance) ||
                total < 0 ||
                storedBalance < 0
            ) {
                return res.status(400).json({
                    error: "Invalid order payment amounts"
                });
            }

            // Calculate the actual paid amount from payment history.
            const paymentSummary = db.prepare(`
                SELECT
                    COALESCE(SUM(amount_paise), 0) AS total_paid
                FROM payments
                WHERE order_id = ?
                  AND payment_status = 'paid'
            `).get(orderId);

            const recordedPaid = Number(paymentSummary.total_paid);

            if (
                !Number.isSafeInteger(recordedPaid) ||
                recordedPaid < 0
            ) {
                return res.status(400).json({
                    error: "Invalid payment history"
                });
            }

            // Support older orders whose advance is not in payment history.
            const legacyAdvance = db.prepare(`
                SELECT
                    advance_amount_paise,
                    razorpay_payment_id
                FROM orders
                WHERE id = ?
            `).get(orderId);

            const verifiedAdvance =
                legacyAdvance.razorpay_payment_id
                    ? Number(legacyAdvance.advance_amount_paise)
                    : 0;

            const totalPaid = Math.max(
                recordedPaid,
                verifiedAdvance
            );

            const balanceDue = Math.max(0, total - totalPaid);

            if (
                balanceDue > 0 ||
                order.payment_status !== "paid"
            ) {
                return res.status(400).json({
                    error: "This order cannot be completed until the full payment has been received.",
                    balanceDuePaise: balanceDue
                });
            }
        }


const result = db.prepare(`
    UPDATE orders
    SET status = ?,
        print_status = ?
    WHERE id = ?
`).run(status, status, orderId);

        if (result.changes === 0) {
            return res.status(404).json({
                error: "Order not found"
            });
        }

        let deliveryEmailSent = false;
        if (status === "completed" && order.status !== "completed") {
            try {
                const emailResult = await sendOrderNotification(orderId, "delivery_confirmation", { allowResend: false });
                deliveryEmailSent = emailResult.sent;
            } catch (emailError) {
                console.error("Delivery confirmation email processing failed:", emailError.message);
            }
        }
        return res.json({
            success: true,
            message: "Order status updated successfully",
            orderId: orderId,
            status: status,
            deliveryEmailSent
        });

    } catch (error) {
        console.error(
            "Order status update failed:",
            error.message
        );

        return res.status(500).json({
            error: "Could not update order status"
        });
    }
});

// Customer registration: email, phone, or both are accepted.
app.post("/customer/register", customerAuthLimiter, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body || {};

        const cleanName = typeof name === "string" ? name.trim() : "";
        const cleanEmail = typeof email === "string" && email.trim()
            ? email.trim().toLowerCase()
            : null;
        const cleanPhone = typeof phone === "string" && phone.trim()
            ? phone.trim()
            : null;

        const validEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

        const validPassword =
            typeof password === "string" &&
            password.length >= 9 &&
            password.length <= 72 &&
            /[A-Z]/.test(password) &&
            /\d/.test(password) &&
            /[^A-Za-z0-9]/.test(password);

        if (
            !/^[A-Za-z]+(?: [A-Za-z]+)*$/.test(cleanName) ||
            cleanName.length > 100 ||
            (!cleanEmail && !cleanPhone) ||
            (cleanEmail && (cleanEmail.length > 254 || !validEmail(cleanEmail))) ||
            (cleanPhone && !/^\d{10}$/.test(cleanPhone)) ||
            !validPassword
        ) {
            return res.status(400).json({
                error: "Enter a name using English letters only, a valid email and/or 10-digit phone number, and a password with at least 9 characters including an uppercase letter, a number, and a special character."
            });
        }

        const duplicate = db.prepare(`
            SELECT id FROM customers
            WHERE (? IS NOT NULL AND email = ? COLLATE NOCASE)
               OR (? IS NOT NULL AND phone = ?)
            LIMIT 1
        `).get(cleanEmail, cleanEmail, cleanPhone, cleanPhone);

        if (duplicate) {
            return res.status(409).json({
                error: "An account with this email or phone number already exists."
            });
        }

        const customerId = crypto.randomUUID();
        const passwordHash = await bcrypt.hash(password, 12);

        db.prepare(`
            INSERT INTO customers (id, name, email, phone, password_hash)
            VALUES (?, ?, ?, ?, ?)
        `).run(customerId, cleanName, cleanEmail, cleanPhone, passwordHash);

        return res.status(201).json({
            success: true,
            message: "Customer account created successfully. Please log in."
        });
    } catch (error) {
        if (String(error.message).includes("UNIQUE constraint failed")) {
            return res.status(409).json({
                error: "An account with this email or phone number already exists."
            });
        }

        console.error("Customer registration failed:", error.message);

        return res.status(500).json({
            error: "Could not create customer account."
        });
    }
});

// Customer login accepts either an email address or a phone number. Sessions expire after 24 hours.
app.post("/customer/login", customerAuthLimiter, async (req, res) => {
    try {
        const { identifier, email, phone, password } = req.body || {};
        const loginIdentifier = typeof identifier === "string" && identifier.trim()
            ? identifier.trim()
            : (typeof email === "string" && email.trim() ? email.trim() : (typeof phone === "string" ? phone.trim() : ""));
        if (!loginIdentifier || typeof password !== "string" || password.length > 72 || !process.env.JWT_SECRET) {
            return res.status(400).json({ error: "Enter your email or phone number and password." });
        }
        const customer = db.prepare(`
            SELECT id, name, email, phone, password_hash
            FROM customers
            WHERE (email IS NOT NULL AND email = ? COLLATE NOCASE) OR (phone IS NOT NULL AND phone = ?)
            LIMIT 1
        `).get(loginIdentifier, loginIdentifier);
        if (!customer || !(await bcrypt.compare(password, customer.password_hash))) {
            return res.status(401).json({ error: "Invalid email/phone number or password." });
        }
        const token = jwt.sign({ role: "customer", customerId: customer.id }, process.env.JWT_SECRET, {
            expiresIn: "24h", issuer: "goprint-backend", audience: "goprint-customer"
        });
        return res.json({ success: true, token, expiresIn: 86400, customer: { id: customer.id, name: customer.name, email: customer.email || null, phone: customer.phone || null } });
    } catch (error) {
        console.error("Customer login failed:", error.message);
        return res.status(500).json({ error: "Could not log in." });
    }
});

// ============================================
// CUSTOMER PASSWORD RECOVERY
// ============================================

const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many password recovery requests. Please try again later."
    }
});

const resetPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many reset attempts. Please try again later."
    }
});

const RESET_OTP_EXPIRY_MS = 10 * 60 * 1000;
const RESET_OTP_COOLDOWN_MS = 60 * 1000;
const RESET_OTP_MAX_ATTEMPTS = 5;

function hashResetOtp(customerId, otp) {
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        throw new Error("JWT_SECRET is not configured.");
    }

    return crypto
        .createHmac("sha256", secret)
        .update(`${customerId}:${otp}`)
        .digest("hex");
}

function safeOtpCompare(expectedHash, suppliedHash) {
    if (
        typeof expectedHash !== "string" ||
        typeof suppliedHash !== "string" ||
        !/^[a-f0-9]{64}$/i.test(expectedHash) ||
        !/^[a-f0-9]{64}$/i.test(suppliedHash)
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        Buffer.from(expectedHash, "hex"),
        Buffer.from(suppliedHash, "hex")
    );
}

function passwordRecoveryResponse(res) {
    return res.status(200).json({
        message:
            "If an account with a registered email exists, a recovery code will be sent."
    });
}


// --------------------------------------------
// REQUEST PASSWORD RESET OTP
// --------------------------------------------

app.post(
    "/customer/forgot-password",
    forgotPasswordLimiter,
    async (req, res) => {
        try {
            const identifier =
                typeof req.body.identifier === "string"
                    ? req.body.identifier.trim()
                    : "";

            if (!identifier || identifier.length > 254) {
                return passwordRecoveryResponse(res);
            }

            const normalized = identifier.toLowerCase();

            const customer = db.prepare(`
                SELECT id, name, email
                FROM customers
                WHERE LOWER(email) = ?
                   OR phone = ?
                LIMIT 1
            `).get(normalized, identifier);

            // Do not reveal whether the account exists.
            if (!customer || !customer.email) {
                return passwordRecoveryResponse(res);
            }

            // Require a complete email configuration.
            if (
                !process.env.SMTP_HOST ||
                !process.env.SMTP_USER ||
                !process.env.SMTP_PASS ||
                !process.env.EMAIL_FROM
            ) {
                console.error(
                    "Password recovery unavailable: SMTP configuration is incomplete."
                );

                return passwordRecoveryResponse(res);
            }

            const now = Date.now();

            // Enforce a cooldown between OTP requests.
            const recentOtp = db.prepare(`
                SELECT created_at
                FROM password_reset_otps
                WHERE customer_id = ?
                ORDER BY created_at DESC
                LIMIT 1
            `).get(String(customer.id));

            if (
                recentOtp &&
                now - Number(recentOtp.created_at) <
                    RESET_OTP_COOLDOWN_MS
            ) {
                return passwordRecoveryResponse(res);
            }

            const otp = crypto
                .randomInt(100000, 1000000)
                .toString();

            const otpHash = hashResetOtp(
                String(customer.id),
                otp
            );

            // Invalidate older recovery codes.
            db.prepare(`
                UPDATE password_reset_otps
                SET used = 1
                WHERE customer_id = ?
                  AND used = 0
            `).run(String(customer.id));

            // Store only the OTP hash.
            db.prepare(`
                INSERT INTO password_reset_otps (
                    customer_id,
                    otp_hash,
                    expires_at,
                    attempts,
                    max_attempts,
                    used,
                    created_at
                )
                VALUES (?, ?, ?, 0, ?, 0, ?)
            `).run(
                String(customer.id),
                otpHash,
                now + RESET_OTP_EXPIRY_MS,
                RESET_OTP_MAX_ATTEMPTS,
                now
            );

            try {
                await mailTransport.sendMail({
                    from: process.env.EMAIL_FROM,
                    to: customer.email,
                    subject: "GoPrint Password Recovery Code",
                    text:
                        `Hello ${customer.name || "Customer"},\n\n` +
                        `Your GoPrint password recovery code is: ${otp}\n\n` +
                        `This code expires in 10 minutes.\n` +
                        `You have a maximum of five verification attempts.\n\n` +
                        `If you did not request this code, you can ignore this email.\n\n` +
                        `GoPrint Support`
                });
            } catch (emailError) {
                // Do not leave an unusable code active.
                db.prepare(`
                    UPDATE password_reset_otps
                    SET used = 1
                    WHERE customer_id = ?
                      AND otp_hash = ?
                `).run(String(customer.id), otpHash);

                console.error(
                    "Password recovery email delivery failed:",
                    emailError.message
                );
            }

            return passwordRecoveryResponse(res);
        } catch (error) {
            console.error(
                "Forgot-password error:",
                error.message
            );

            return passwordRecoveryResponse(res);
        }
    }
);


// --------------------------------------------
// RESET CUSTOMER PASSWORD
// --------------------------------------------

app.post(
    "/customer/reset-password",
    resetPasswordLimiter,
    async (req, res) => {
        try {
            const identifier =
                typeof req.body.identifier === "string"
                    ? req.body.identifier.trim()
                    : "";

            const otp =
                typeof req.body.otp === "string"
                    ? req.body.otp.trim()
                    : "";

            const newPassword =
                typeof req.body.newPassword === "string"
                    ? req.body.newPassword
                    : "";

            if (
                !identifier ||
                identifier.length > 254 ||
                !/^\d{6}$/.test(otp)
            ) {
                return res.status(400).json({
                    error: "Invalid or expired recovery code."
                });
            }

            if (
                newPassword.length < 9 ||
                newPassword.length > 72 ||
                !/[A-Z]/.test(newPassword) ||
                !/[0-9]/.test(newPassword) ||
                !/[^A-Za-z0-9\s]/.test(newPassword)
            ) {
                return res.status(400).json({
                    error:
                        "Password must be 9–72 characters and contain an uppercase letter, a number, and a special character."
                });
            }

            const normalized = identifier.toLowerCase();

            const customer = db.prepare(`
                SELECT id
                FROM customers
                WHERE LOWER(email) = ?
                   OR phone = ?
                LIMIT 1
            `).get(normalized, identifier);

            if (!customer) {
                return res.status(400).json({
                    error: "Invalid or expired recovery code."
                });
            }

            const customerId = String(customer.id);
            const now = Date.now();

            const resetRecord = db.prepare(`
                SELECT id, otp_hash, expires_at, attempts,
                       max_attempts, used
                FROM password_reset_otps
                WHERE customer_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            `).get(customerId);

            if (
                !resetRecord ||
                resetRecord.used !== 0 ||
                Number(resetRecord.expires_at) <= now ||
                Number(resetRecord.attempts) >=
                    Number(resetRecord.max_attempts)
            ) {
                return res.status(400).json({
                    error: "Invalid or expired recovery code."
                });
            }

            const suppliedHash = hashResetOtp(
                customerId,
                otp
            );

            if (
                !safeOtpCompare(
                    resetRecord.otp_hash,
                    suppliedHash
                )
            ) {
                const nextAttempts =
                    Number(resetRecord.attempts) + 1;

                db.prepare(`
                    UPDATE password_reset_otps
                    SET attempts = ?,
                        used = CASE
                            WHEN ? >= max_attempts THEN 1
                            ELSE used
                        END
                    WHERE id = ?
                      AND used = 0
                `).run(
                    nextAttempts,
                    nextAttempts,
                    resetRecord.id
                );

                return res.status(400).json({
                    error: "Invalid or expired recovery code."
                });
            }

            // Hash the new password before saving it.
            const passwordHash = await bcrypt.hash(
                newPassword,
                12
            );

            // Update the password and consume all reset codes
            // in one database transaction.
            const updatePassword = db.transaction(() => {
                const currentRecord = db.prepare(`
                    SELECT id, otp_hash, expires_at,
                           attempts, max_attempts, used
                    FROM password_reset_otps
                    WHERE id = ?
                      AND customer_id = ?
                `).get(resetRecord.id, customerId);

                if (
                    !currentRecord ||
                    currentRecord.used !== 0 ||
                    Number(currentRecord.expires_at) <= Date.now() ||
                    Number(currentRecord.attempts) >=
                        Number(currentRecord.max_attempts) ||
                    !safeOtpCompare(
                        currentRecord.otp_hash,
                        suppliedHash
                    )
                ) {
                    return false;
                }

                const result = db.prepare(`
                    UPDATE customers
                    SET password_hash = ?
                    WHERE id = ?
                `).run(passwordHash, customerId);

                if (result.changes !== 1) {
                    throw new Error(
                        "Customer password update failed."
                    );
                }

                db.prepare(`
                    UPDATE password_reset_otps
                    SET used = 1
                    WHERE customer_id = ?
                      AND used = 0
                `).run(customerId);

                return true;
            });

            const updated = updatePassword();

            if (!updated) {
                return res.status(400).json({
                    error: "Invalid or expired recovery code."
                });
            }

            return res.status(200).json({
                message:
                    "Password reset successfully. You can now log in."
            });
        } catch (error) {
            console.error(
                "Reset-password error:",
                error.message
            );

            return res.status(500).json({
                error: "Unable to reset password right now."
            });
        }
    }
);

// Health check
app.get("/", (req, res) => {
    res.json({
        message: "GoPrint payment backend is running"
    });
});

// Create one Razorpay order for one or more PDF documents.
app.post("/create-order", requireCustomer, async (req, res) => {
    let razorpayOrder = null;

    try {
        const {
            document_settings,
            documentSettings,
            customerName,
            customerPhone,
            collectionMethod,
            collectionLocation,
            collegeYear,
            collegeDepartment,
            collegeSection,
            rollNumber,
            advancePercentage
        } = req.body || {};

        // Support the Android app's JSON array and legacy single-PDF requests.
        let documents = document_settings ?? documentSettings;

        if (typeof documents === "string") {
            try {
                documents = JSON.parse(documents);
            } catch {
                return res.status(400).json({
                    success: false,
                    error: "Invalid document settings JSON"
                });
            }
        }

        if (documents === undefined || documents === null) {
            const {
                documentName,
                pageCount,
                copies,
                colour,
                paperSize,
                sides,
                orientation,
                pagesPerSheet,
                colourPages
            } = req.body || {};

            documents = [{
                pdf_name: documentName,
                page_count: pageCount,
                copies,
                colour,
                paperSize,
                sides,
                orientation,
                pagesPerSheet,
                colourPages
            }];
        }

        if (
            !Array.isArray(documents) ||
            documents.length < 1 ||
            documents.length > 20
        ) {
            return res.status(400).json({
                success: false,
                error: "Select between 1 and 20 PDF documents"
            });
        }

        if (
            ![30, 40, 50, 60, 70, 80, 90, 100]
                .includes(Number(advancePercentage)) ||
            typeof customerName !== "string" ||
            !customerName.trim() ||
            customerName.trim().length > 100 ||
            typeof customerPhone !== "string" ||
            !/^\d{10}$/.test(customerPhone.trim()) ||
            typeof collectionMethod !== "string" ||
            !collectionMethod.trim() ||
            typeof collectionLocation !== "string" ||
            !collectionLocation.trim()
        ) {
            return res.status(400).json({
                success: false,
                error: "Missing or invalid customer, collection, or advance payment details"
            });
        }

        const advancePercent = Number(advancePercentage);

        // Validate and calculate each document independently.
        const validatedDocuments = [];
        let totalAmountPaise = 0;
        let totalPrintedPages = 0;

        for (let index = 0; index < documents.length; index++) {
            const doc = documents[index];

            if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid settings for document ${index + 1}`
                });
            }

            const name =
                typeof doc.pdf_name === "string"
                    ? doc.pdf_name.trim()
                    : typeof doc.documentName === "string"
                        ? doc.documentName.trim()
                        : "";

            const pageCount = Number(doc.page_count ?? doc.pageCount);
            const copies = Number(doc.copies);
            const colour = doc.colour ?? doc.color;
            const paperSize = doc.paperSize ?? doc.paper_size;
            const sides = doc.sides ?? doc.print_sides;
            const orientation = doc.orientation;
            const pagesPerSheet = Number(
                doc.pagesPerSheet ?? doc.pages_per_sheet ?? 1
            );

            const colourPagesValue =
                doc.colourPages ?? doc.colour_pages ?? "";

            const colourPages =
                typeof colourPagesValue === "string"
                    ? colourPagesValue.trim()
                    : "";

            if (
                !name ||
                name.length > 255 ||
                !Number.isSafeInteger(pageCount) ||
                pageCount < 1 ||
                pageCount > 10000 ||
                !Number.isSafeInteger(copies) ||
                copies < 1 ||
                copies > 1000
            ) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid filename, page count, or copies for document ${index + 1}`
                });
            }

            if (
                !["Colour", "Black and White"].includes(colour) ||
                !["Single-sided", "Double-sided"].includes(sides) ||
                paperSize !== "A4" ||
                !["Portrait", "Landscape"].includes(orientation) ||
                ![1, 2, 4, 9].includes(pagesPerSheet)
            ) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid print settings for document ${index + 1}`
                });
            }

            if (
                colourPages.length > 20000 ||
                (colourPages && colour === "Black and White")
            ) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid colour-page selection for document ${index + 1}`
                });
            }

            const selectedColourPages = new Set();

            if (colourPages) {
                for (const part of colourPages.split(",")) {
                    const match = part.trim().match(
                        /^(\d+)(?:\s*-\s*(\d+))?$/
                    );

                    if (!match) {
                        return res.status(400).json({
                            success: false,
                            error: `Invalid colour-page selection for document ${index + 1}`
                        });
                    }

                    const start = Number(match[1]);
                    const end = match[2] ? Number(match[2]) : start;

                    if (
                        !Number.isSafeInteger(start) ||
                        !Number.isSafeInteger(end) ||
                        start < 1 ||
                        end < start ||
                        end > pageCount ||
                        end - start > 10000
                    ) {
                        return res.status(400).json({
                            success: false,
                            error: `Colour-page numbers are out of range for document ${index + 1}`
                        });
                    }

                    for (let page = start; page <= end; page++) {
                        selectedColourPages.add(page);
                    }
                }
            }

            // When no specific ranges are supplied, Colour means every page.
            const colourPageCount = colourPages
                ? selectedColourPages.size
                : colour === "Colour"
                    ? pageCount
                    : 0;

            const blackWhitePageCount = pageCount - colourPageCount;

            let documentTotalPaise = Math.round(
                (
                    colourPageCount * 500 +
                    blackWhitePageCount * 250
                ) * copies
            );

            // Apply the existing 10% double-sided discount per document.
            if (sides === "Double-sided") {
                documentTotalPaise = Math.round(
                    documentTotalPaise * 0.90
                );
            }

            if (
                !Number.isSafeInteger(documentTotalPaise) ||
                documentTotalPaise <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid calculated price for document ${index + 1}`
                });
            }

            totalAmountPaise += documentTotalPaise;
            totalPrintedPages += pageCount * copies;

            if (
                !Number.isSafeInteger(totalAmountPaise) ||
                totalAmountPaise > 10000000
            ) {
                return res.status(400).json({
                    success: false,
                    error: "Combined order total exceeds the permitted limit"
                });
            }

            validatedDocuments.push({
                document_index: index,
                document_name: name,
                page_count: pageCount,
                copies,
                color_mode: colour === "Colour" ? "colour" : "black_white",
                paper_size: paperSize,
                print_sides: sides === "Double-sided" ? "double" : "single",
                pages_per_sheet: pagesPerSheet,
                orientation,
                colour_pages: colourPages,
                document_total_paise: documentTotalPaise
            });
        }

        if (
            !Number.isSafeInteger(totalAmountPaise) ||
            totalAmountPaise <= 0
        ) {
            return res.status(400).json({
                success: false,
                error: "Calculated order total is invalid"
            });
        }

        // Calculate the advance and remaining balance.
if (
    !Number.isSafeInteger(totalAmountPaise) ||
    totalAmountPaise < 100
) {
    return res.status(400).json({
        success: false,
        error: "Order total must be at least ₹1."
    });
}

let advanceAmountPaise = Math.round(
    totalAmountPaise * advancePercent / 100
);

// Razorpay requires at least ₹1 for this order.
advanceAmountPaise = Math.max(100, advanceAmountPaise);

// Never charge more than the order total.
advanceAmountPaise = Math.min(
    advanceAmountPaise,
    totalAmountPaise
);

let balanceAmountPaise =
    totalAmountPaise - advanceAmountPaise;

if (
    !Number.isSafeInteger(advanceAmountPaise) ||
    !Number.isSafeInteger(balanceAmountPaise) ||
    advanceAmountPaise <= 0 ||
    balanceAmountPaise < 0
) {
    return res.status(400).json({
        success: false,
        error: "Invalid calculated advance or balance."
    });
}

        // Razorpay has a minimum payment amount. Reject too-small orders
        // instead of charging more than the calculated order total.
        if (advanceAmountPaise < 100) {
            return res.status(400).json({
                success: false,
                error: "The calculated advance is below Razorpay's minimum payment amount. Increase the order total or choose a higher advance percentage."
            });
        }

        // Keep the legacy order columns populated using the first document.
        // The new table stores the settings for every selected document.
        const firstDocument = validatedDocuments[0];

        // One Razorpay order for the combined advance.
        razorpayOrder = await razorpay.orders.create({
            amount: advanceAmountPaise,
            currency: "INR",
            receipt: `gp_${Date.now()}_${randomUUID().slice(0, 8)}`
        });

        // Save the GoPrint order and every document atomically.
        const saveOrderAndDocuments = db.transaction(() => {
            const savedOrder = db.prepare(`
                INSERT INTO orders (
                    customer_id,
                    razorpay_order_id,
                    document_name,
                    copies,
                    color_mode,
                    paper_size,
                    print_sides,
                    amount_paise,
                    status,
                    page_count,
                    pages_per_sheet,
                    orientation,
                    colour_pages,
                    total_amount_paise,
                    advance_percentage,
                    advance_amount_paise,
                    balance_amount_paise,
                    payment_status,
                    print_status,
                    customer_name,
                    customer_phone,
                    collection_method,
                    collection_location,
                    college_year,
                    college_department,
                    college_section,
                    roll_number
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?
                )
            `).run(
                req.customer.id,
                razorpayOrder.id,
                validatedDocuments.map(d => d.document_name).join(", "),
                firstDocument.copies,
                firstDocument.color_mode,
                firstDocument.paper_size,
                firstDocument.print_sides,
                advanceAmountPaise,
                "pending",
                firstDocument.page_count,
                firstDocument.pages_per_sheet,
                firstDocument.orientation,
                firstDocument.colour_pages,
                totalAmountPaise,
                advancePercent,
                advanceAmountPaise,
                balanceAmountPaise,
                "pending",
                "pending",
                customerName.trim(),
                customerPhone.trim(),
                collectionMethod.trim(),
                collectionLocation.trim(),
                typeof collegeYear === "string" ? collegeYear.trim() : "",
                typeof collegeDepartment === "string" ? collegeDepartment.trim() : "",
                typeof collegeSection === "string" ? collegeSection.trim() : "",
                typeof rollNumber === "string" ? rollNumber.trim() : ""
            );

            const localOrderId = Number(savedOrder.lastInsertRowid);

            const insertDocument = db.prepare(`
                INSERT INTO order_documents (
                    order_id,
                    document_index,
                    document_name,
                    page_count,
                    copies,
                    color_mode,
                    paper_size,
                    print_sides,
                    pages_per_sheet,
                    orientation,
                    colour_pages
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            for (const doc of validatedDocuments) {
                insertDocument.run(
                    localOrderId,
                    doc.document_index,
                    doc.document_name,
                    doc.page_count,
                    doc.copies,
                    doc.color_mode,
                    doc.paper_size,
                    doc.print_sides,
                    doc.pages_per_sheet,
                    doc.orientation,
                    doc.colour_pages
                );
            }

            return localOrderId;
        });

        const localOrderId = saveOrderAndDocuments();

        return res.json({
            success: true,
            localOrderId,
            orderId: razorpayOrder.id,
            amount: razorpayOrder.amount,
            totalAmount: totalAmountPaise,
            advanceAmount: advanceAmountPaise,
            balanceAmount: balanceAmountPaise,
            advancePercentage: advancePercent,
            currency: razorpayOrder.currency,
            keyId: razorpayKeyId,
            documentCount: validatedDocuments.length,
            documents: validatedDocuments.map(doc => ({
                documentName: doc.document_name,
                pageCount: doc.page_count,
                copies: doc.copies,
                totalAmount: doc.document_total_paise
            }))
        });

    } catch (error) {
        console.error("Order creation failed:", error.message);

        return res.status(500).json({
            success: false,
            error: "Could not create the order. Please try again."
        });
    }
});

// Verify payment and record the advance payment in payment history.
app.post("/verify-payment", requireCustomer, async (req, res) => {
    try {
        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature
        } = req.body;

        if (
            typeof razorpay_order_id !== "string" ||
            typeof razorpay_payment_id !== "string" ||
            typeof razorpay_signature !== "string"
        ) {
            return res.status(400).json({
                verified: false,
                error: "Missing payment verification details"
            });
        }

        // Find the GoPrint order saved during checkout creation.
        const savedOrder = db.prepare(`
            SELECT *
            FROM orders
            WHERE razorpay_order_id = ?
        `).get(razorpay_order_id);

        if (!savedOrder) {
            return res.status(404).json({
                verified: false,
                error: "GoPrint order was not found"
            });
        }

        // Ensure the order belongs to the logged-in customer.
        if (savedOrder.customer_id !== req.customer.id) {
            return res.status(403).json({
                verified: false,
                error: "You are not authorized to verify this order"
            });
        }

        // Verify Razorpay's payment signature.
        const expectedSignature = crypto
            .createHmac("sha256", razorpayKeySecret)
            .update(
                razorpay_order_id + "|" + razorpay_payment_id
            )
            .digest("hex");

        if (!/^[a-f0-9]{64}$/i.test(razorpay_signature)) {
            return res.status(400).json({ verified: false, error: "Invalid payment signature" });
        }
        const received = Buffer.from(razorpay_signature, "hex");
        const expected = Buffer.from(expectedSignature, "hex");

        if (
            received.length !== expected.length ||
            !crypto.timingSafeEqual(received, expected)
        ) {
            return res.status(400).json({
                verified: false,
                error: "Invalid payment signature"
            });
        }

        // Fetch payment information directly from Razorpay.
        const razorpayOrder =
            await razorpay.orders.fetch(razorpay_order_id);

        const payment =
            await razorpay.payments.fetch(razorpay_payment_id);

        // Verify that Razorpay confirms the correct captured amount.
        if (
            payment.order_id !== razorpayOrder.id ||
            payment.status !== "captured" ||
            razorpayOrder.status !== "paid" ||
            payment.currency !== "INR" ||
            payment.amount !== savedOrder.advance_amount_paise ||
            razorpayOrder.amount !== savedOrder.advance_amount_paise
        ) {
            return res.status(400).json({
                verified: false,
                error: "Payment is not captured or does not match the order"
            });
        }

        /*
         * Record the payment and update the order in one transaction.
         * If either database operation fails, SQLite rolls back both.
         */
        const recordAdvancePayment = db.transaction(() => {
            const currentOrder = db.prepare(`
                SELECT
                    id,
                    razorpay_payment_id,
                    payment_status,
                    advance_amount_paise,
                    total_amount_paise
                FROM orders
                WHERE razorpay_order_id = ?
            `).get(razorpay_order_id);

            if (!currentOrder) {
                throw new Error("ORDER_NOT_FOUND");
            }

            // Safely handle a retry of the same payment.
            if (
                currentOrder.razorpay_payment_id === payment.id
            ) {
                const existingPayment = db.prepare(`
                    SELECT id
                    FROM payments
                    WHERE razorpay_payment_id = ?
                      AND order_id = ?
                      AND payment_status = 'paid'
                `).get(
                    payment.id,
                    currentOrder.id
                );

                // Repair the history record if this is a legacy order.
                if (!existingPayment) {
                    db.prepare(`
                        INSERT INTO payments (
                            order_id,
                            amount_paise,
                            payment_method,
                            payment_type,
                            payment_status,
                            razorpay_order_id,
                            razorpay_payment_id
                        )
                        VALUES (
                            ?, ?, 'razorpay', 'advance',
                            'paid', ?, ?
                        )
                    `).run(
                        currentOrder.id,
                        currentOrder.advance_amount_paise,
                        razorpay_order_id,
                        payment.id
                    );
                }

                return {
                    orderId: currentOrder.id,
                    paymentStatus: currentOrder.payment_status,
                    newlyRecorded: false,
                    advanceAmountPaise: currentOrder.advance_amount_paise
                };
            }

            // Never overwrite a different payment already recorded.
            if (
                currentOrder.payment_status !== "pending" ||
                currentOrder.razorpay_payment_id
            ) {
                throw new Error("ORDER_ALREADY_PROCESSED");
            }

            // Determine whether this advance covers the full order.
            const paymentStatus =
                currentOrder.advance_amount_paise >=
                currentOrder.total_amount_paise
                    ? "paid"
                    : "advance_paid";

            // Record the verified Razorpay advance payment.
            db.prepare(`
                INSERT INTO payments (
                    order_id,
                    amount_paise,
                    payment_method,
                    payment_type,
                    payment_status,
                    razorpay_order_id,
                    razorpay_payment_id
                )
                VALUES (
                    ?, ?, 'razorpay', 'advance',
                    'paid', ?, ?
                )
            `).run(
                currentOrder.id,
                currentOrder.advance_amount_paise,
                razorpay_order_id,
                payment.id
            );

            // Update the GoPrint order.
            const updateResult = db.prepare(`
                UPDATE orders
                SET razorpay_payment_id = ?,
                    payment_status = ?,
                    status = 'confirmed'
                WHERE id = ?
                  AND payment_status = 'pending'
            `).run(
                payment.id,
                paymentStatus,
                currentOrder.id
            );

            if (updateResult.changes !== 1) {
                throw new Error("ORDER_UPDATE_FAILED");
            }

            return {
                orderId: currentOrder.id,
                paymentStatus: paymentStatus,
                newlyRecorded: true,
                advanceAmountPaise: currentOrder.advance_amount_paise
            };
        });

        let recordedPayment;

        try {
            recordedPayment = recordAdvancePayment();
        } catch (error) {
            if (error.message === "ORDER_NOT_FOUND") {
                return res.status(404).json({
                    verified: false,
                    error: "GoPrint order was not found"
                });
            }

            if (error.message === "ORDER_ALREADY_PROCESSED") {
                return res.status(409).json({
                    verified: false,
                    error: "Order has already been processed"
                });
            }

            console.error(
                "Advance payment recording failed:",
                error.message
            );

            return res.status(500).json({
                verified: false,
                error: "Payment was verified, but the order could not be updated. Please contact support."
            });
        }

        let receiptEmailSent = false;
        try {
            const emailResult = await sendOrderNotification(recordedPayment.orderId, "payment_receipt", {
                paymentType: "advance", amountPaise: recordedPayment.advanceAmountPaise,
                paymentId: payment.id, allowResend: recordedPayment.newlyRecorded
            });
            receiptEmailSent = emailResult.sent;
        } catch (emailError) {
            console.error("Advance receipt email processing failed:", emailError.message);
        }
        const orderSummary = db.prepare(`SELECT id, customer_name, customer_phone, document_name, total_amount_paise, advance_amount_paise, balance_amount_paise, payment_status, created_at FROM orders WHERE id = ?`).get(recordedPayment.orderId);
        return res.json({
            verified: true,
            message: "Payment verified and order updated",
            orderId: razorpay_order_id,
            localOrderId: recordedPayment.orderId,
            paymentId: payment.id,
            paymentStatus: recordedPayment.paymentStatus,
            receiptEmailSent,
            order: orderSummary
        });

    } catch (error) {
        console.error(
            "Payment verification failed:",
            error.message
        );

        return res.status(500).json({
            verified: false,
            error: "Could not verify payment"
        });
    }
});

// Create a Razorpay order for the customer's outstanding balance.
app.post(
    "/orders/:id/create-balance-payment",
    requireCustomer,
    async (req, res) => {
        try {
            const orderId = Number(req.params.id);

            if (
                !Number.isSafeInteger(orderId) ||
                orderId < 1
            ) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid order ID"
                });
            }

            // Find the order and confirm ownership.
            const order = db.prepare(`
                SELECT
                    id,
                    customer_id,
                    total_amount_paise,
                    advance_amount_paise,
                    balance_amount_paise,
                    payment_status,
                    razorpay_payment_id
                FROM orders
                WHERE id = ?
            `).get(orderId);

            if (!order) {
                return res.status(404).json({
                    success: false,
                    error: "Order not found"
                });
            }

            if (order.customer_id !== req.customer.id) {
                return res.status(403).json({
                    success: false,
                    error: "You are not authorized to pay for this order"
                });
            }

            // Validate the order's payment amounts.
            const totalAmount = Number(order.total_amount_paise);
            const advanceAmount = Number(order.advance_amount_paise);

            if (
                !Number.isSafeInteger(totalAmount) ||
                !Number.isSafeInteger(advanceAmount) ||
                totalAmount <= 0 ||
                advanceAmount < 0 ||
                advanceAmount > totalAmount
            ) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid order payment amounts"
                });
            }

            // The initial online advance must have been verified.
            if (
                !["advance_paid", "paid"].includes(
                    order.payment_status
                ) ||
                !order.razorpay_payment_id
            ) {
                return res.status(400).json({
                    success: false,
                    error: "The online advance payment must be verified first"
                });
            }

            // Calculate all successfully recorded payments.
            const paymentSummary = db.prepare(`
                SELECT
                    COALESCE(SUM(amount_paise), 0) AS total_paid,
                    COALESCE(
                        SUM(
                            CASE
                                WHEN payment_type = 'advance'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ) AS advance_payment_count
                FROM payments
                WHERE order_id = ?
                  AND payment_status = 'paid'
            `).get(orderId);

            const recordedPaid = Number(paymentSummary.total_paid);

            if (
                !Number.isSafeInteger(recordedPaid) ||
                recordedPaid < 0
            ) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid payment history"
                });
            }

            // Support older orders whose advance is not in payment history.
            const legacyAdvance =
                Number(paymentSummary.advance_payment_count) === 0
                    ? advanceAmount
                    : 0;

            const totalPaid = recordedPaid + legacyAdvance;
            const balanceDue = totalAmount - totalPaid;

            if (
                !Number.isSafeInteger(totalPaid) ||
                balanceDue < 0
            ) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid order payment totals"
                });
            }

            if (balanceDue === 0) {
                return res.status(400).json({
                    success: false,
                    error: "This order has no outstanding balance"
                });
            }

            // Create a Razorpay order for the exact remaining balance.
            const razorpayOrder = await razorpay.orders.create({
                amount: balanceDue,
                currency: "INR",
                receipt: `gpb_${orderId}_${randomUUID().slice(0, 8)}`
            });

            // Save a pending balance-payment record.
            db.prepare(`
                INSERT INTO payments (
                    order_id,
                    amount_paise,
                    payment_method,
                    payment_type,
                    payment_status,
                    razorpay_order_id
                )
                VALUES (?, ?, 'razorpay', 'balance', 'pending', ?)
            `).run(
                orderId,
                balanceDue,
                razorpayOrder.id
            );

            return res.json({
                success: true,
                message: "Balance payment order created",
                localOrderId: orderId,
                razorpayOrderId: razorpayOrder.id,
                amount: balanceDue,
                currency: "INR",
                keyId: razorpayKeyId
            });

        } catch (error) {
            console.error(
                "Balance payment order creation failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                error: "Could not create the balance payment order"
            });
        }
    }
);

// Verify and record the customer's online balance payment.
app.post(
    "/orders/:id/verify-balance-payment",
    requireCustomer,
    async (req, res) => {
        try {
            const orderId = Number(req.params.id);

            const {
                razorpay_order_id,
                razorpay_payment_id,
                razorpay_signature
            } = req.body;

            if (
                !Number.isSafeInteger(orderId) ||
                orderId < 1 ||
                typeof razorpay_order_id !== "string" ||
                typeof razorpay_payment_id !== "string" ||
                typeof razorpay_signature !== "string"
            ) {
                return res.status(400).json({
                    verified: false,
                    error: "Invalid payment verification details"
                });
            }

            // Confirm the order exists and belongs to this customer.
            const order = db.prepare(`
                SELECT
                    id,
                    customer_id,
                    total_amount_paise,
                    advance_amount_paise,
                    payment_status,
                    razorpay_payment_id
                FROM orders
                WHERE id = ?
            `).get(orderId);

            if (!order) {
                return res.status(404).json({
                    verified: false,
                    error: "Order not found"
                });
            }

            if (order.customer_id !== req.customer.id) {
                return res.status(403).json({
                    verified: false,
                    error: "You are not authorized to verify this order"
                });
            }

            // Find the pending payment created for this order.
            const balancePayment = db.prepare(`
                SELECT
                    id,
                    amount_paise,
                    payment_status,
                    razorpay_payment_id
                FROM payments
                WHERE order_id = ?
                  AND razorpay_order_id = ?
                  AND payment_type = 'balance'
            `).get(orderId, razorpay_order_id);

            if (!balancePayment) {
                return res.status(404).json({
                    verified: false,
                    error: "Balance payment record not found"
                });
            }

            // Verify the Razorpay signature.
            const expectedSignature = crypto
                .createHmac("sha256", razorpayKeySecret)
                .update(
                    razorpay_order_id + "|" + razorpay_payment_id
                )
                .digest("hex");

            if (
                !/^[a-f0-9]{64}$/i.test(razorpay_signature)
            ) {
                return res.status(400).json({
                    verified: false,
                    error: "Invalid payment signature"
                });
            }

            const receivedSignature = Buffer.from(
                razorpay_signature,
                "hex"
            );

            const expectedSignatureBuffer = Buffer.from(
                expectedSignature,
                "hex"
            );

            if (
                receivedSignature.length !==
                    expectedSignatureBuffer.length ||
                !crypto.timingSafeEqual(
                    receivedSignature,
                    expectedSignatureBuffer
                )
            ) {
                return res.status(400).json({
                    verified: false,
                    error: "Invalid payment signature"
                });
            }

            // Confirm payment details directly with Razorpay.
            const razorpayOrder =
                await razorpay.orders.fetch(razorpay_order_id);

            const payment =
                await razorpay.payments.fetch(razorpay_payment_id);

            if (
                payment.order_id !== razorpayOrder.id ||
                payment.status !== "captured" ||
                razorpayOrder.status !== "paid" ||
                payment.currency !== "INR" ||
                razorpayOrder.currency !== "INR" ||
                payment.amount !== balancePayment.amount_paise ||
                razorpayOrder.amount !== balancePayment.amount_paise
            ) {
                return res.status(400).json({
                    verified: false,
                    error: "Payment is not captured or the amount does not match"
                });
            }

            // Record the payment and update the order atomically.
            const recordBalancePayment = db.transaction(() => {
                const currentPayment = db.prepare(`
                    SELECT
                        id,
                        amount_paise,
                        payment_status,
                        razorpay_payment_id
                    FROM payments
                    WHERE order_id = ?
                      AND razorpay_order_id = ?
                      AND payment_type = 'balance'
                `).get(orderId, razorpay_order_id);

                if (!currentPayment) {
                    throw new Error("BALANCE_PAYMENT_NOT_FOUND");
                }

                // Safely allow a retry of the same verified payment.
                if (
                    currentPayment.payment_status === "paid" &&
                    currentPayment.razorpay_payment_id === payment.id
                ) {
                    const updatedOrder = db.prepare(`
                        SELECT payment_status, balance_amount_paise
                        FROM orders
                        WHERE id = ?
                    `).get(orderId);

                    return {
                        paymentStatus: updatedOrder.payment_status,
                        balanceDue: Number(updatedOrder.balance_amount_paise),
                        newlyRecorded: false,
                        amountPaise: currentPayment.amount_paise
                    };
                }

                // Never overwrite another payment or a previously paid record.
                if (
                    currentPayment.payment_status !== "pending" ||
                    currentPayment.razorpay_payment_id
                ) {
                    throw new Error("BALANCE_PAYMENT_ALREADY_PROCESSED");
                }

                // Record the successful Razorpay payment.
                const updatePayment = db.prepare(`
                    UPDATE payments
                    SET payment_status = 'paid',
                        razorpay_payment_id = ?
                    WHERE id = ?
                      AND payment_status = 'pending'
                `).run(
                    payment.id,
                    currentPayment.id
                );

                if (updatePayment.changes !== 1) {
                    throw new Error("BALANCE_PAYMENT_UPDATE_FAILED");
                }

                // Calculate all successfully recorded payments.
                const summary = db.prepare(`
                    SELECT
                        COALESCE(SUM(amount_paise), 0) AS total_paid,
                        COALESCE(
                            SUM(
                                CASE
                                    WHEN payment_type = 'advance'
                                    THEN 1
                                    ELSE 0
                                END
                            ),
                            0
                        ) AS advance_count
                    FROM payments
                    WHERE order_id = ?
                      AND payment_status = 'paid'
                `).get(orderId);

                const recordedPaid = Number(summary.total_paid);

                if (
                    !Number.isSafeInteger(recordedPaid) ||
                    recordedPaid < 0
                ) {
                    throw new Error("INVALID_PAYMENT_HISTORY");
                }

                // Support older orders missing an advance history record.
                const legacyAdvance =
                    Number(summary.advance_count) === 0
                        ? Number(order.advance_amount_paise)
                        : 0;

                const totalPaid = recordedPaid + legacyAdvance;
                const totalAmount = Number(order.total_amount_paise);

                if (
                    !Number.isSafeInteger(totalPaid) ||
                    !Number.isSafeInteger(totalAmount) ||
                    totalAmount <= 0 ||
                    totalPaid > totalAmount
                ) {
                    throw new Error("INVALID_PAYMENT_TOTAL");
                }

                const balanceDue = totalAmount - totalPaid;

                const newPaymentStatus =
                    balanceDue === 0 ? "paid" : "advance_paid";

                const updateOrder = db.prepare(`
                    UPDATE orders
                    SET balance_amount_paise = ?,
                        payment_status = ?
                    WHERE id = ?
                `).run(
                    balanceDue,
                    newPaymentStatus,
                    orderId
                );

                if (updateOrder.changes !== 1) {
                    throw new Error("ORDER_UPDATE_FAILED");
                }

                return {
                    paymentStatus: newPaymentStatus,
                    balanceDue: balanceDue,
                    newlyRecorded: true,
                    amountPaise: currentPayment.amount_paise
                };
            });

            let result;

            try {
                result = recordBalancePayment();
            } catch (error) {
                if (error.message === "BALANCE_PAYMENT_NOT_FOUND") {
                    return res.status(404).json({
                        verified: false,
                        error: "Balance payment record not found"
                    });
                }

                if (
                    error.message ===
                    "BALANCE_PAYMENT_ALREADY_PROCESSED"
                ) {
                    return res.status(409).json({
                        verified: false,
                        error: "This balance payment has already been processed"
                    });
                }

                console.error(
                    "Balance payment recording failed:",
                    error.message
                );

                return res.status(500).json({
                    verified: false,
                    error: "Payment verification succeeded, but the order could not be updated. Please contact support."
                });
            }

            let receiptEmailSent = false;
            try {
                const emailResult = await sendOrderNotification(orderId, "payment_receipt", {
                    paymentType: "balance", amountPaise: result.amountPaise,
                    paymentId: payment.id, allowResend: result.newlyRecorded
                });
                receiptEmailSent = emailResult.sent;
            } catch (emailError) {
                console.error("Balance receipt email processing failed:", emailError.message);
            }
            const orderSummary = db.prepare(`SELECT id, customer_name, customer_phone, document_name, total_amount_paise, advance_amount_paise, balance_amount_paise, payment_status, created_at FROM orders WHERE id = ?`).get(orderId);
            return res.json({
                verified: true,
                message: "Balance payment verified successfully",
                orderId: orderId,
                localOrderId: orderId,
                paymentId: payment.id,
                paymentStatus: result.paymentStatus,
                balanceDuePaise: result.balanceDue,
                receiptEmailSent,
                order: orderSummary
            });

        } catch (error) {
            console.error(
                "Balance payment verification failed:",
                error.message
            );

            return res.status(500).json({
                verified: false,
                error: "Could not verify the balance payment"
            });
        }
    }
);

// Upload a PDF to an existing, payment-verified customer order
app.post(
    "/orders/:id/upload-pdf",
    requireCustomer,
    pdfUpload.array("pdfs", 20),
    (req, res) => {
        const uploadedFiles = req.files || [];
        const savedPaths = [];

        try {
            const orderId = Number(req.params.id);
            const customerId = req.customer.id;

            if (!Number.isSafeInteger(orderId) || orderId <= 0) {
                for (const file of uploadedFiles) {
                    fs.unlink(file.path, () => {});
                }

                return res.status(400).json({
                    success: false,
                    message: "Invalid order ID."
                });
            }

            if (uploadedFiles.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "Please upload the order's PDF documents."
                });
            }

            const order = db.prepare(`
                SELECT id, customer_id, payment_status, pdf_file_path
                FROM orders
                WHERE id = ?
            `).get(orderId);

            if (!order) {
                for (const file of uploadedFiles) {
                    fs.unlink(file.path, () => {});
                }

                return res.status(404).json({
                    success: false,
                    message: "Order not found."
                });
            }

            if (String(order.customer_id) !== String(customerId)) {
                for (const file of uploadedFiles) {
                    fs.unlink(file.path, () => {});
                }

                return res.status(403).json({
                    success: false,
                    message: "You cannot upload documents for this order."
                });
            }

            if (
                order.payment_status !== "paid" &&
                order.payment_status !== "advance_paid"
            ) {
                for (const file of uploadedFiles) {
                    fs.unlink(file.path, () => {});
                }

                return res.status(403).json({
                    success: false,
                    message: "Verify the advance payment before uploading documents."
                });
            }

            const documents = db.prepare(`
                SELECT id, document_index, document_name, pdf_file_path
                FROM order_documents
                WHERE order_id = ?
                ORDER BY document_index ASC
            `).all(orderId);

            if (documents.length === 0) {
                for (const file of uploadedFiles) {
                    fs.unlink(file.path, () => {});
                }

                return res.status(400).json({
                    success: false,
                    message: "No documents are registered for this order."
                });
            }

            if (uploadedFiles.length !== documents.length) {
                for (const file of uploadedFiles) {
                    fs.unlink(file.path, () => {});
                }

                return res.status(400).json({
                    success: false,
                    message:
                        `This order contains ${documents.length} document(s). ` +
                        `Please upload exactly ${documents.length} PDF file(s).`
                });
            }

            for (const file of uploadedFiles) {
                const fd = fs.openSync(file.path, "r");

                try {
                    const header = Buffer.alloc(5);
                    const bytesRead = fs.readSync(fd, header, 0, 5, 0);

                    if (
                        bytesRead !== 5 ||
                        header.toString("ascii") !== "%PDF-"
                    ) {
                        throw new Error(
                            "One or more uploaded files are not valid PDFs."
                        );
                    }
                } finally {
                    fs.closeSync(fd);
                }

                savedPaths.push(file.path);
            }

            const updateDocument = db.prepare(`
                UPDATE order_documents
                SET pdf_file_path = ?
                WHERE id = ? AND order_id = ?
            `);

            const updateOrder = db.prepare(`
                UPDATE orders
                SET pdf_file_path = ?
                WHERE id = ?
            `);

            const saveAll = db.transaction(() => {
                documents.forEach((document, index) => {
                    updateDocument.run(
                        uploadedFiles[index].path,
                        document.id,
                        orderId
                    );
                });

                // Preserve compatibility with older code that expects
                // the first PDF path on the orders table.
                updateOrder.run(uploadedFiles[0].path, orderId);
            });

            saveAll();

            return res.json({
                success: true,
                message: "All order documents were uploaded successfully.",
                orderId,
                documentCount: uploadedFiles.length,
                documents: documents.map((document, index) => ({
                    documentId: document.id,
                    documentName: document.document_name,
                    uploaded: true
                }))
            });
        } catch (error) {
            console.error("Multi-document PDF upload error:", error);

            for (const filePath of savedPaths) {
                fs.unlink(filePath, () => {});
            }

            for (const file of uploadedFiles) {
                if (!savedPaths.includes(file.path)) {
                    fs.unlink(file.path, () => {});
                }
            }

            return res.status(500).json({
                success: false,
                message: error.message.includes("not valid PDFs")
                    ? error.message
                    : "Could not upload the order documents. Please try again."
            });
        }
    }
);


 // Get order history for the authenticated customer, including every PDF.
app.get("/orders", requireCustomer, (req, res) => {
    try {
        const customerId = req.customer.id;

        // Only return orders belonging to the logged-in customer.
        const orders = db.prepare(`
            SELECT
                id,
                razorpay_order_id,
                razorpay_payment_id,
                document_name,
                copies,
                color_mode,
                paper_size,
                print_sides,
                page_count,
                pages_per_sheet,
                orientation,
                colour_pages,
                amount_paise,
                total_amount_paise,
                advance_amount_paise,
                balance_amount_paise,
                advance_percentage,
                payment_status,
                print_status,
                status,
                customer_name,
                customer_phone,
                collection_method,
                collection_location,
                college_year,
                college_department,
                college_section,
                roll_number,
                created_at
            FROM orders
            WHERE customer_id = ?
            ORDER BY created_at DESC, id DESC
        `).all(customerId);

        // Retrieve all PDFs associated with each order.
        const getDocuments = db.prepare(`
            SELECT
                id,
                document_index,
                document_name,
                page_count,
                copies,
                color_mode,
                paper_size,
                print_sides,
                pages_per_sheet,
                orientation,
                colour_pages,
                CASE
                    WHEN pdf_file_path IS NOT NULL
                     AND pdf_file_path != ''
                    THEN 1
                    ELSE 0
                END AS has_pdf
            FROM order_documents
            WHERE order_id = ?
            ORDER BY document_index ASC, id ASC
        `);

        const getPayments = db.prepare(`
            SELECT
                id,
                amount_paise,
                payment_method,
                payment_type,
                payment_status,
                razorpay_payment_id,
                created_at
            FROM payments
            WHERE order_id = ?
              AND payment_status = 'paid'
            ORDER BY created_at ASC, id ASC
        `);

        const getLegacyPdf = db.prepare(`
            SELECT
                id,
                document_name,
                page_count,
                copies,
                color_mode,
                paper_size,
                print_sides,
                pages_per_sheet,
                orientation,
                colour_pages,
                CASE
                    WHEN pdf_file_path IS NOT NULL
                     AND pdf_file_path != ''
                    THEN 1
                    ELSE 0
                END AS has_pdf
            FROM orders
            WHERE id = ?
        `);

        const orderHistory = orders.map(order => {
            let documents = getDocuments.all(order.id);

            // Compatibility fallback for legacy orders that do not
            // have rows in order_documents.
            if (documents.length === 0) {
                const legacy = getLegacyPdf.get(order.id);

                if (legacy) {
                    documents = [{
                        id: null,
                        document_index: 0,
                        document_name: legacy.document_name,
                        page_count: legacy.page_count,
                        copies: legacy.copies,
                        color_mode: legacy.color_mode,
                        paper_size: legacy.paper_size,
                        print_sides: legacy.print_sides,
                        pages_per_sheet: legacy.pages_per_sheet,
                        orientation: legacy.orientation,
                        colour_pages: legacy.colour_pages,
                        has_pdf: legacy.has_pdf
                    }];
                }
            }

            const payments = getPayments.all(order.id);

            const recordedPaidPaise = payments.reduce(
                (sum, payment) => sum + Number(payment.amount_paise || 0),
                0
            );

            // Older orders may have a verified advance payment
            // without an entry in the payments table.
            const hasAdvancePayment = payments.some(
                payment => payment.payment_type === "advance"
            );

            const paidPaise = Math.max(
                recordedPaidPaise,
                !hasAdvancePayment && order.razorpay_payment_id
                    ? Number(order.advance_amount_paise || 0)
                    : 0
            );

            return {
                ...order,
                documents,
                documentCount: documents.length,
                payments,
                totalPaidPaise: paidPaise,
                totalPages: documents.reduce(
                    (sum, document) =>
                        sum +
                        Number(document.page_count || 0) *
                        Number(document.copies || 1),
                    0
                )
            };
        });

        return res.json({
            success: true,
            count: orderHistory.length,
            orders: orderHistory
        });

    } catch (error) {
        console.error(
            "Failed to retrieve customer order history:",
            error.message
        );

        return res.status(500).json({
            success: false,
            error: "Could not retrieve order history"
        });
    }
});

// Admin-only download for an individual PDF in a multi-document order.
app.get(
    "/admin/orders/:id/documents/:documentId/pdf",
    requireAdmin,
    (req, res) => {
        try {
            const orderId = Number(req.params.id);
            const documentId = Number(req.params.documentId);

            if (
                !Number.isSafeInteger(orderId) || orderId < 1 ||
                !Number.isSafeInteger(documentId) || documentId < 1
            ) {
                return res.status(400).json({
                    error: "Invalid order or document ID"
                });
            }

            const document = db.prepare(`
                SELECT id, order_id, document_name, pdf_file_path
                FROM order_documents
                WHERE id = ? AND order_id = ?
            `).get(documentId, orderId);

            if (!document) {
                return res.status(404).json({
                    error: "Document not found for this order"
                });
            }

            if (!document.pdf_file_path) {
                return res.status(404).json({
                    error: "No PDF file has been uploaded for this document"
                });
            }

            const savedPath = path.resolve(document.pdf_file_path);
            const privateDirectory = path.resolve(uploadDirectory);

            // Only allow PDFs directly inside the private upload directory.
            if (
                path.dirname(savedPath) !== privateDirectory ||
                path.extname(savedPath).toLowerCase() !== ".pdf"
            ) {
                return res.status(403).json({
                    error: "Invalid PDF file location"
                });
            }

            if (!fs.existsSync(savedPath)) {
                return res.status(404).json({
                    error: "The uploaded PDF file could not be found"
                });
            }

            const safeName = path.basename(
                document.document_name || `Document_${document.id}.pdf`
            ).replace(/[\r\n"]/g, "_");

            res.download(savedPath, safeName, error => {
                if (error) {
                    console.error(
                        "Individual PDF download failed:",
                        error.message
                    );

                    if (!res.headersSent) {
                        res.status(500).json({
                            error: "Could not download this PDF"
                        });
                    }
                }
            });
        } catch (error) {
            console.error(
                "Individual PDF retrieval failed:",
                error.message
            );

            if (!res.headersSent) {
                res.status(500).json({
                    error: "Could not retrieve this PDF"
                });
            }
        }
    }
);

// Admin-only endpoint: download a customer's uploaded PDF
app.get("/admin/orders/:id/pdf", requireAdmin, (req, res) => {
    try {
        const orderId = Number(req.params.id);

        if (!Number.isSafeInteger(orderId) || orderId < 1) {
            return res.status(400).json({
                error: "Invalid order ID"
            });
        }

        const order = db.prepare(`
            SELECT document_name, pdf_file_path
            FROM orders
            WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                error: "Order not found"
            });
        }

        if (!order.pdf_file_path) {
            return res.status(404).json({
                error: "No PDF has been uploaded for this order"
            });
        }

        // Only allow files stored directly in the private upload folder.
        const savedPath = path.resolve(order.pdf_file_path);

        if (
            path.dirname(savedPath) !== path.resolve(uploadDirectory) ||
            path.extname(savedPath).toLowerCase() !== ".pdf"
        ) {
            return res.status(403).json({
                error: "Invalid PDF file location"
            });
        }

        if (!fs.existsSync(savedPath)) {
            return res.status(404).json({
                error: "The PDF file could not be found"
            });
        }

        res.download(savedPath, `GoPrint_Order_${orderId}.pdf`, (error) => {
            if (error) {
                console.error("PDF download failed:", error.message);

                if (!res.headersSent) {
                    res.status(500).json({
                        error: "Could not download the PDF"
                    });
                }
            }
        });

    } catch (error) {
        console.error("Admin PDF retrieval failed:", error.message);

        return res.status(500).json({
            error: "Could not retrieve the PDF"
        });
    }
});

// Customer: retrieve payment receipt details for an order
app.get(
    "/orders/:id/receipt",
    requireCustomer,
    (req, res) => {
        try {
            const orderId = Number(req.params.id);

            if (
                !Number.isSafeInteger(orderId) ||
                orderId < 1
            ) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid order ID"
                });
            }

            // Retrieve the order only if it belongs to this customer.
            const order = db.prepare(`
                SELECT
                    id,
                    customer_id,
                    document_name,
                    razorpay_payment_id,
                    total_amount_paise,
                    advance_amount_paise,
                    balance_amount_paise,
                    payment_status,
                    created_at
                FROM orders
                WHERE id = ?
                  AND customer_id = ?
            `).get(orderId, req.customer.id);

            if (!order) {
                return res.status(404).json({
                    success: false,
                    error: "Order not found"
                });
            }

            // Return successfully recorded payments only.
            const payments = db.prepare(`
                SELECT
                    id,
                    amount_paise,
                    payment_method,
                    payment_type,
                    payment_status,
                    razorpay_payment_id,
                    recorded_by,
                    created_at
                FROM payments
                WHERE order_id = ?
                  AND payment_status = 'paid'
                ORDER BY created_at ASC, id ASC
            `).all(orderId);

            // Support older orders whose advance payment predates
            // the payment-history table.
            let receiptPayments = payments;

            const hasAdvanceRecord = payments.some(
                payment => payment.payment_type === "advance"
            );

            if (
                !hasAdvanceRecord &&
                order.razorpay_payment_id &&
                Number(order.advance_amount_paise) > 0
            ) {
                receiptPayments = [
                    {
                        id: null,
                        amount_paise: order.advance_amount_paise,
                        payment_method: "razorpay",
                        payment_type: "advance",
                        payment_status: "paid",
                        razorpay_payment_id:
                            order.razorpay_payment_id,
                        recorded_by: "",
                        created_at: order.created_at,
                        legacy_record: true
                    },
                    ...payments
                ];
            }

            const totalPaidPaise = receiptPayments.reduce(
                (sum, payment) =>
                    sum + Number(payment.amount_paise),
                0
            );

            return res.json({
                success: true,
                receipt: {
                    order_id: order.id,
                    document_name: order.document_name,
                    total_amount_paise:
                        order.total_amount_paise,
                    advance_amount_paise:
                        order.advance_amount_paise,
                    balance_amount_paise:
                        order.balance_amount_paise,
                    payment_status: order.payment_status,
                    order_date: order.created_at,
                    total_paid_paise: totalPaidPaise,
                    payments: receiptPayments
                }
            });

        } catch (error) {
            console.error(
                "Receipt retrieval failed:",
                error.message
            );

            console.log(
    "Invoice document name:",
    order.document_name
);

            return res.status(500).json({
                success: false,
                error: "Could not retrieve payment receipt"
            });
        }
    }
);


// Start the backend server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`GoPrint backend running on port ${PORT}`);
});