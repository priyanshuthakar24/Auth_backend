const mongoose = require('mongoose');
const MONGODB_URI = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.c77xwlg.mongodb.net/${process.env.MONGODB_DEFAULT_DATABASE}`;

exports.connectDB = async () => {
    try {
        console.log(MONGODB_URI)
        const conn = await mongoose.connect(MONGODB_URI);
        console.log(`mongodb connected:${conn.connection.host}`);
    } catch (error) {
        console.log(error.message);
        process.exit(1);
    }
};