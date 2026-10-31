const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "goprint.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// --------------------------------------------------
// ORDERS TABLE
// --------------------------------------------------

db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id TEXT NOT NULL,
        razorpay_order_id TEXT UNIQUE,
        razorpay_payment_id TEXT,
        document_name TEXT NOT NULL,
        copies INTEGER NOT NULL DEFAULT 1,
        color_mode TEXT NOT NULL DEFAULT 'black_white',
        paper_size TEXT NOT NULL DEFAULT 'A4',
        print_sides TEXT NOT NULL DEFAULT 'single',
        amount_paise INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
`);

const newColumns = {
    page_count: "INTEGER NOT NULL DEFAULT 0",
    pages_per_sheet: "INTEGER NOT NULL DEFAULT 1",
    orientation: "TEXT NOT NULL DEFAULT 'Portrait'",
    colour_pages: "TEXT NOT NULL DEFAULT ''",
    pdf_file_path: "TEXT",

    total_amount_paise: "INTEGER NOT NULL DEFAULT 0",
    advance_percentage: "INTEGER NOT NULL DEFAULT 30",
    advance_amount_paise: "INTEGER NOT NULL DEFAULT 0",
    balance_amount_paise: "INTEGER NOT NULL DEFAULT 0",

    payment_status: "TEXT NOT NULL DEFAULT 'pending'",
    print_status: "TEXT NOT NULL DEFAULT 'pending'",

    customer_name: "TEXT NOT NULL DEFAULT ''",
    customer_phone: "TEXT NOT NULL DEFAULT ''",
    collection_method: "TEXT NOT NULL DEFAULT ''",
    collection_location: "TEXT NOT NULL DEFAULT ''",

    college_year: "TEXT NOT NULL DEFAULT ''",
    college_department: "TEXT NOT NULL DEFAULT ''",
    college_section: "TEXT NOT NULL DEFAULT ''",
    roll_number: "TEXT NOT NULL DEFAULT ''"
};

const existingOrderColumns = db.prepare(
    "PRAGMA table_info(orders)"
).all().map(column => column.name);

for (const [columnName, columnDefinition] of Object.entries(newColumns)) {
    if (!existingOrderColumns.includes(columnName)) {
        db.exec(
            `ALTER TABLE orders ADD COLUMN ${columnName} ${columnDefinition}`
        );

        console.log(`Added database column: ${columnName}`);
    }
}

// --------------------------------------------------
// ORDER DOCUMENTS TABLE
// Supports multiple PDFs within one order.
// Existing orders are migrated without deleting their data.
// --------------------------------------------------

db.exec(`
    CREATE TABLE IF NOT EXISTS order_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        order_id INTEGER NOT NULL,

        document_index INTEGER NOT NULL DEFAULT 0,

        document_name TEXT NOT NULL,

        page_count INTEGER NOT NULL DEFAULT 0,
        copies INTEGER NOT NULL DEFAULT 1,

        color_mode TEXT NOT NULL DEFAULT 'black_white',
        paper_size TEXT NOT NULL DEFAULT 'A4',
        print_sides TEXT NOT NULL DEFAULT 'single',

        pages_per_sheet INTEGER NOT NULL DEFAULT 1,
        orientation TEXT NOT NULL DEFAULT 'Portrait',
        colour_pages TEXT NOT NULL DEFAULT '',

        pdf_file_path TEXT,

        created_at TEXT NOT NULL DEFAULT (datetime('now')),

        UNIQUE (order_id, document_index),

        FOREIGN KEY (order_id)
            REFERENCES orders(id)
            ON DELETE RESTRICT
    );
`);

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_order_documents_order_id
    ON order_documents(order_id);
`);

// Migrate existing orders into the new table.
// Each existing order is initially represented by one document.
// Existing orders and their payment records remain unchanged.

const migrateExistingOrderDocuments = db.transaction(() => {
    db.exec(`
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
            colour_pages,
            pdf_file_path
        )
        SELECT
            o.id,
            0,
            o.document_name,
            o.page_count,
            o.copies,
            o.color_mode,
            o.paper_size,
            o.print_sides,
            o.pages_per_sheet,
            o.orientation,
            o.colour_pages,
            o.pdf_file_path
        FROM orders AS o
        WHERE NOT EXISTS (
            SELECT 1
            FROM order_documents AS od
            WHERE od.order_id = o.id
        );
    `);
});

migrateExistingOrderDocuments();

console.log("Multi-document order support is ready.");

// --------------------------------------------------
// CUSTOMERS TABLE
// Supports email, phone, or both.
// Existing customer IDs and password hashes are kept.
// --------------------------------------------------

const customersTableExists = db.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type = 'table' AND name = 'customers'
`).get();

if (!customersTableExists) {
    db.exec(`
        CREATE TABLE customers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT COLLATE NOCASE UNIQUE,
            phone TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),

            CHECK (
                (email IS NOT NULL AND length(trim(email)) > 0)
                OR
                (phone IS NOT NULL AND length(trim(phone)) > 0)
            )
        );
    `);

    console.log("Created customers table with email support.");
} else {
    const customerColumns = db.prepare(
        "PRAGMA table_info(customers)"
    ).all();

    const customerColumnNames = customerColumns.map(column => column.name);

    const phoneColumn = customerColumns.find(
        column => column.name === "phone"
    );

    const emailColumnExists = customerColumnNames.includes("email");
    const phoneIsRequired = phoneColumn ? phoneColumn.notnull === 1 : false;

    // Rebuild the table when the old schema requires a phone number
    // or when email support is missing.
    if (phoneIsRequired || !emailColumnExists) {
        const rebuildCustomers = db.transaction(() => {
            db.exec(`
                CREATE TABLE customers_migration (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT COLLATE NOCASE UNIQUE,
                    phone TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),

                    CHECK (
                        (email IS NOT NULL AND length(trim(email)) > 0)
                        OR
                        (phone IS NOT NULL AND length(trim(phone)) > 0)
                    )
                );
            `);

            const hasId = customerColumnNames.includes("id");
            const hasName = customerColumnNames.includes("name");
            const hasPhone = customerColumnNames.includes("phone");
            const hasPasswordHash = customerColumnNames.includes("password_hash");
            const hasCreatedAt = customerColumnNames.includes("created_at");

            if (
                !hasId ||
                !hasName ||
                !hasPhone ||
                !hasPasswordHash
            ) {
                throw new Error(
                    "Unexpected customers schema. Migration stopped to protect customer data."
                );
            }

            const emailExpression = emailColumnExists
                ? "NULLIF(trim(email), '')"
                : "NULL";

            const createdAtExpression = hasCreatedAt
                ? "created_at"
                : "datetime('now')";

            db.exec(`
                INSERT INTO customers_migration (
                    id,
                    name,
                    email,
                    phone,
                    password_hash,
                    created_at
                )
                SELECT
                    id,
                    name,
                    ${emailExpression},
                    NULLIF(trim(phone), ''),
                    password_hash,
                    ${createdAtExpression}
                FROM customers;
            `);

            db.exec("DROP TABLE customers;");
            db.exec("ALTER TABLE customers_migration RENAME TO customers;");
        });

        rebuildCustomers();

        console.log("Customers table migrated; existing accounts preserved.");
    } else {
        // Normalize empty contact values to NULL.
        // SQLite UNIQUE indexes allow multiple NULL values.
        db.exec(`
            UPDATE customers
            SET email = NULL
            WHERE email IS NOT NULL AND trim(email) = '';
        `);

        db.exec(`
            UPDATE customers
            SET phone = NULL
            WHERE phone IS NOT NULL AND trim(phone) = '';
        `);
    }
}

// Ensure email and phone remain unique on existing compatible schemas.
db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_email_unique
    ON customers(email COLLATE NOCASE)
    WHERE email IS NOT NULL;
`);

db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_phone_unique
    ON customers(phone)
    WHERE phone IS NOT NULL;
`);

// --------------------------------------------------
// PAYMENTS TABLE
// --------------------------------------------------

db.exec(`
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        order_id INTEGER NOT NULL,

        amount_paise INTEGER NOT NULL
            CHECK (amount_paise > 0),

        payment_method TEXT NOT NULL
            CHECK (payment_method IN ('razorpay', 'cash')),

        payment_type TEXT NOT NULL
            CHECK (payment_type IN ('advance', 'balance')),

        payment_status TEXT NOT NULL DEFAULT 'pending'
            CHECK (payment_status IN ('pending', 'paid', 'failed')),

        razorpay_order_id TEXT UNIQUE,
        razorpay_payment_id TEXT UNIQUE,

        recorded_by TEXT NOT NULL DEFAULT '',

        created_at TEXT NOT NULL DEFAULT (datetime('now')),

        FOREIGN KEY (order_id)
            REFERENCES orders(id)
            ON DELETE RESTRICT
    );
`);

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_payments_order_id
    ON payments(order_id);
`);

// --------------------------------------------------
// EMAIL NOTIFICATION TRACKING
// Prevents repeated notifications for the same event.
// --------------------------------------------------

db.exec(`
    CREATE TABLE IF NOT EXISTS email_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        order_id INTEGER NOT NULL,

        notification_type TEXT NOT NULL
            CHECK (
                notification_type IN (
                    'payment_receipt',
                    'delivery_confirmation'
                )
            ),

        recipient_email TEXT NOT NULL,

        notification_status TEXT NOT NULL DEFAULT 'pending'
            CHECK (
                notification_status IN (
                    'pending',
                    'sent',
                    'failed'
                )
            ),

        attempts INTEGER NOT NULL DEFAULT 0,

        last_error TEXT NOT NULL DEFAULT '',

        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),

        UNIQUE (order_id, notification_type),

        FOREIGN KEY (order_id)
            REFERENCES orders(id)
            ON DELETE RESTRICT
    );
`);

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_email_notifications_status
    ON email_notifications(notification_status);
`);

// --------------------------------------------------
// CUSTOMER PASSWORD RESET OTPs
// Stores OTP hashes, not plaintext OTPs.
// --------------------------------------------------

db.exec(`
    CREATE TABLE IF NOT EXISTS password_reset_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        customer_id TEXT NOT NULL,

        otp_hash TEXT NOT NULL,

        expires_at INTEGER NOT NULL,

        attempts INTEGER NOT NULL DEFAULT 0
            CHECK (attempts >= 0),

        max_attempts INTEGER NOT NULL DEFAULT 5
            CHECK (max_attempts > 0),

        used INTEGER NOT NULL DEFAULT 0
            CHECK (used IN (0, 1)),

        created_at INTEGER NOT NULL,

        FOREIGN KEY (customer_id)
            REFERENCES customers(id)
            ON DELETE CASCADE
    );
`);

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_customer
    ON password_reset_otps(customer_id);
`);

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_expiry
    ON password_reset_otps(expires_at);
`);

console.log("GoPrint database is ready.");

module.exports = db;