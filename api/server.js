const express = require("express");
const helmet = require("helmet");
const bcryptjs = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const usersRouter = require("../users/users-router.js");
const authRouter = require("../auth/auth-router.js");
const dbConnection = require("../data/db-config");
const authenticate = require("../auth/authenticate-middleware.js");

const server = express();

const sessionConfiguration = {
    name: "monster", // default value is sid
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!", // key for encryption
    cookie: {
        maxAge: 1000 * 60 * 10,
        secure: process.env.USE_SECURE_COOKIES || false, // send the cookie only over https (secure connections)
        httpOnly: true, // prevent JS code on client from accessing this cookie
    },
    resave: false,
    saveUninitialized: true, // read docs, it's related to GDPR compliance
    store: new KnexSessionStore({
        knex: dbConnection,
        tablename: "sessions",
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 1000 * 60 * 30, // time to check and remove expired sessions from database
    }),
};

server.use(session(sessionConfiguration)); // enables session support
server.use(helmet());
server.use(express.json());
// server.use(cors());

server.use("/api/users", authenticate, usersRouter);
server.use("/api/auth", authRouter);

server.get("/", (req, res) => {
    res.json({ api: "up" });
});

server.get("/hash", (req, res) => {
    const password = req.headers.authorization;
    const secret = req.headers.secret;

    const hash = hashString(secret);

    if (password === "mellon") {
        res.json({ welcome: "friend", secret, hash });
    } else {
        res.status(401).json({ you: "cannot pass!" });
    }
});

function hashString(str) {
    // use bcryptjs to hash the str argument and return the hash
    const rounds = process.env.HASH_ROUNDS || 4;
    const hash = bcryptjs.hashSync(str, rounds);

    return hash;
}



module.exports = server;