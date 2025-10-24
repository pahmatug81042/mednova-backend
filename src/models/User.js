const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");
const { sanitizePlain } = require("../utils/sanitize");

// Roles: combined simplified + enterprise roles
const ROLES = [
    "patient",
    "clinician",
    'admin',
    'ai_auditor',
    'researcher',
    'data_steward'
];

// Very strong password policy
const PASSWORD_POLICY = {
    minLength: 14,
    // must contain uppercase, lowercase, digit, special char
    regex: /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+={}[\]|\\:;"'<>,.?/~`])/,
    // simple blacklist (extendable)
    blacklist: [
        "password",
        "123456",
        "123456789",
        "qwerty",
        "letmein",
        "admin",
        "welcome",
        "iloveyou"
    ]
};

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || "12", 10);

const { Schema } = mongoose;

const UserSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true,
        validate: {
            validator: (v) => validator.isEmail(v || ''),
            message: 'Invalid email address'
        }
    },

    // passwordHash is stored for local auth accounts only
    passwordHash: {
        type: String,
    },

    // display name (sanitized)
    name: {
        type: String,
        trim: true,
        set: v => sanitizePlain(v)
    },

    // roles - default to clinician for created accounts unless overridden
    roles: {
        type: [String],
        enum: ROLES,
        default: ["clinician"]
    },

    // provider for SSO (local or provider name)
    provider: {
        type: String,
        enum: ['local', 'google', 'azure', 'saml', 'okta'],
        default: 'local'
    },

    // providerId for SSO mapped identity
    providerId: {
        type: String,
        index: true,
        sparse: true
    },

    isActive: {
        type: Boolean,
        default: true
    },

    // other fields
    createdAt: { type: Date, default: Date.now },
    lastLoginAt: { type: Date }
}, {
    timestamps: true
});

// Instance method: compare password
UserSchema.methods.comparePassword = async function (candidate) {
    if (!this.passwordHash) return false;
    return bcrypt.compare(candidate, this.passwordHash);
};

// Instance method: hasRole
UserSchema.methods.hasRole = function (role) {
    return Array.isArray(this.roles) && this.roles.includes(role);
};

// Static: validate password strength according to policy
UserSchema.statics.validatePasswordStrength = function (password) {
    if (typeof password !== "string") return { ok: false, reason: "Password must be a string" };
    if (password.length < PASSWORD_POLICY.minLength) {
        return { ok: false, reason: `Password must be at least ${PASSWORD_POLICY.minLength} characters` };
    }
    if (!PASSWORD_POLICY.regex.text(password)) {
        return { ok: false, reason: "Password must include upper and lower case letters, a number, and a special character" };
    }

    const pLower = password.toLowerCase();
    for (const bad of PASSWORD_POLICY.blacklist) {
        if (pLower.includes(bad)) {
            return { ok: false, reason: "Password contains a common or weak substring" };
        }
    }

    // simple checks to avoid repeated sequences or long runs (e.g., 111111, abcdef)
    if (/(\w)\1{5,}/.test(password)) {
        return { ok: false, reason: "Password contains long repeated characters." };
    }
    if (/(012345|123456|abcdef|qwerty)/i.test(password)) {
        return { ok: false, reason: "Password contains common sequential patterns" };
    }

    return { ok: true };
};

// Pre-save hook: hash password if modified and ensure password meets policy
UserSchema.pre("save", async function (next) {
    try {
        // sanitize email and name again just in case
        if (this.isModified("email") && this.email) {
            this.email = String(this.email).trim().toLowerCase();
        }
        if (this.isModified("name") && this.name) {
            this.name = sanitizePlain(this.name);
        }

        // If a password field is set on the instance (raw), we expect callers to set passwordHash directly.
        // For convenience, support "password" virtual during creation.
        const raw = this.password;
        const check = mongoose.model("User").validatePasswordStrength(raw);
        if (!check.ok) {
            const error = new Error(`Weak password: ${check.reason}`);
            error.name = "ValidationError";
            return next(error);
        }
        const hash = await bcrypt.hash(raw, SALT_ROUNDS);
        this.passwordHash = hash;
        // remove plain password if it existed
        this.password = undefined;

        // If passwordHash changes directly, no extra check (assume upstream validated)
        next();
    } catch (error) {
        next(error);
    }
});

// Virtual setter for password to allow creating user with "password" field (won't be persisted)
UserSchema.virtual("password").set(function (pw) {
    // store on the document (transient) so pre-save can pick up
    this._tempPassword = pw;
    this.password = pw; // will be removed in pre-save
});

// Also support reading transient password (rarely needed)
UserSchema.virtual("password").get(function () {
    return undefined;
});

// Export model
module.exports = mongoose.model("User", UserSchema);