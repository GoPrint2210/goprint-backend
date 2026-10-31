const jwt = require("jsonwebtoken");

// Verify that the request belongs to the authenticated admin.
function requireAdmin(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Admin authentication required"
        });
    }

    const token = authorization.slice(7);

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET,
            {
                issuer: "goprint-backend",
                audience: "goprint-admin"
            }
        );

        if (
            decoded.role !== "admin" ||
            decoded.adminId !== process.env.ADMIN_ID
        ) {
            return res.status(403).json({
                error: "Admin access only"
            });
        }

        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired admin token"
        });
    }
}

// Verify that the request belongs to an authenticated customer.
function requireCustomer(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Customer login required"
        });
    }

    const token = authorization.slice(7);

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET,
            {
                issuer: "goprint-backend",
                audience: "goprint-customer"
            }
        );

        if (
            decoded.role !== "customer" ||
            typeof decoded.customerId !== "string" ||
            !decoded.customerId
        ) {
            return res.status(403).json({
                error: "Customer access only"
            });
        }

        req.customer = {
            id: decoded.customerId
        };

        next();
    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired customer token"
        });
    }
}

module.exports = {
    requireAdmin,
    requireCustomer
};