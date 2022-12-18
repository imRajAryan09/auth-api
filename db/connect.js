const mongoose = require("mongoose");
mongoose.set("strictQuery", true);
const connectDB = async (url) => {
	return await mongoose
		.connect(url, {
		})
		.then(() => console.log("connected to db"))
		.catch((err) => {
			console.log("MONGO DB ERROR", err);
		});
};

module.exports = connectDB;
