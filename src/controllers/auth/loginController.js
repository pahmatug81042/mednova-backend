const User = require("../../models/User");
const { generateTokensAndSetCookies } = require("../../utils/auth");

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password required" });
        }

        const user = await User.findOne({ email }).select("+passwordHash");

        if (!user || user.provider !== "local") {
            return res.status(401).json({ message: "Invalid login credentials" });
        }

        const match = await user.comparePassword(password);
        if (!match) {
            return res.status(401).json({ message: "Invalid login credentials" });
        }

        user.lastLoginAt = new Date();
        await user.save();

        await generateTokensAndSetCookies(user, res);

        res.status(200).json({
            message: "Login successful",
            user: {
                id: user._id,
                email: user.email,
                roles: user.roles,
                name: user.name
            }
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error" });
    }
};