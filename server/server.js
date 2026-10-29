const config = require("./config/env");
const app = require("./app");
const connectDB = require("./utils/db");

const PORT = config.PORT;

// Start server
const startServer = async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
};

startServer();
