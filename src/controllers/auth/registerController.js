const User = require("../../models/User");
const { generateTokensAndSetCookies } = require("../../utils/auth");
const { sanitizePlain } = require("../../utils/sanitize");

exports.register = async (req, res) => {
    try {
        const { email, password, name, role } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password required" });
        }

        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ message: "Email already registered" });
        }

        // Very-strong password policy check
        const policy = User.validatePasswordStrength(password);
        if (!policy.ok) {
            return res.status(400).json({ message: policy.reason });
        }

        const safeName = sanitizePlain(name);

        const user = new User({
            email,
            name: safeName,
            provider: "local",
            roles: role ? [role] : undefined
        });

        user.password = password;
        await user.save();

        await generateTokensAndSetCookies(user, res);

        res.status(201).json({
            message: "Account created successfully",
            user: {
                id: user._id,
                email: user.email,
                roles: user.roles,
                name: user.name
            }
        });
    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ message: "Server error" });
    }
};