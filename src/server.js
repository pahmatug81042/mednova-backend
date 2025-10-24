const mongoose = require("mongoose");
const app = require("./app");

const PORT = process.env.PORT || 8000;
const MONGO_URI = process.env.MONGO_URI;

// Connect to MongoDB
mongoose.connect(MONGO_URI)
    .then (() => {
        console.log("Connected to MongoDB");

        app.listen(PORT, () => {
            console.log(`MedNova Backend running on port ${PORT}`);
        });
    })
    .catch((error) => {
        console.error("MongoDB Connection Failed", error);
        process.exit(1);
    });