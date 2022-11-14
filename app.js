const express = require("express");
const app = express();
const port = 3000;
const jwt = require("jsonwebtoken");
const JWT_SECRET = "secret";
app.use(express.json());

const ADMIN = 0;
const USER = 1;

const READ = 10000;
const WRITE = 10001;

const db = {
  users: [
    { user: "admin", pass: "admin", role: ADMIN },
    { user: "user", pass: "user", role: USER },
  ],
  permissions: {
    [ADMIN]: new Set([READ, WRITE]),
    [USER]: new Set([READ]),
  },
};

const get_user_info = (user) => {
  for (const user_obj of db["users"]) {
    if (user_obj.user === user) {
      return user_obj;
    }
  }
  return null;
};

const get_user_token = (user_obj) => {
  return jwt.sign(user_obj, JWT_SECRET);
};

const login_user = (user, pass) => {
  const user_info = get_user_info(user);
  if (user_info === null) {
    return {
      success: false,
      statusCode: 400,
      message: "No such user exists",
    };
  }
  if (pass === user_info.pass) {
    return {
      success: true,
      statusCode: 200,
      token: get_user_token(user_info),
    };
  }
  return {
    success: false,
    statusCode: 401,
    message: "Wrong password",
  };
};

const authenticate = (req, res) => {
  const token = req.get("authorization");
  try {
    const { user, pass, role } = jwt.verify(token, JWT_SECRET);
    return role;
  } catch (err) {
    console.log(err);
    return null;
  }
};

const verify_perms = (role, perms) => {
  const roles = db["permissions"][role];
  for (const p of perms) {
    if (!roles.has(p)) {
      return false;
    }
  }
  return true;
};

const authorize = (perms, handler) => {
  return (req, res) => {
    const role = authenticate(req, res);
    if (role === null) {
      return res.status(401).send("Failed to authenticate");
    }
    const is_verified = verify_perms(role, perms);
    if (is_verified) {
      return handler(req, res);
    }
    return res.status(403).send("Inadequate permissions");
  };
};

app.get(
  "/admin",
  authorize([READ, WRITE], (req, res) => res.send("Welcome admin!"))
);
app.get(
  "/user",
  authorize([READ], (req, res) => res.send("Welcome user!"))
);

app.post("/login", (req, res) => {
  const { user, pass } = req.body;
  if (user == undefined || pass == undefined) {
    return res.status(400).send("Missing user or pass");
  }
  const result = login_user(user, pass);
  res.status(result.statusCode).send(result);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
