import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

const app = express();
const PORT = 3019;
dotenv.config();

app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  return res.status(200).send("Hello Token!");
});

let tokenStorage = {}; // Refresh Token을 저장할 객체

/** Access Token, Refresh Token 발급 API **/
app.post("/tokens", (req, res) => {
  const { id } = req.body;
  const accessToken = createAccessToken(id);
  const refreshToken = createRefreshToken(id);

  // Refresh Token을 가지고 해당 유저의 정보를 서버에 저장합니다.
  tokenStorage[refreshToken] = {
    id: id, // 사용자에게 전달받은 ID를 저장합니다.
    ip: req.ip, // 사용자의 IP 정보를 저장합니다.
    userAgent: req.headers["user-agent"], // 사용자의 User Agent 정보를 저장합니다.
  };

  console.log(tokenStorage);

  res.cookie("accessToken", process.env.ACCESS_TOKEN_SECRET_KEY); // Access Token을 Cookie에 전달한다.
  res.cookie("refreshToken", process.env.REFRESH_TOKEN_SECRET_KEY); // Refresh Token을 Cookie에 전달한다.

  return res
    .status(200)
    .json({ message: "Token이 정상적으로 발급되었습니다." });
});

// Access Token을 생성하는 함수
function createAccessToken(id) {
  const accessToken = jwt.sign(
    { id: id }, // JWT 데이터
    process.env.ACCESS_TOKEN_SECRET_KEY, // Access Token의 비밀 키
    { expiresIn: "1000s" } // Access Token이 10초 뒤에 만료되도록 설정합니다.
  );

  return accessToken;
}

// Refresh Token을 생성하는 함수
function createRefreshToken(id) {
  const refreshToken = jwt.sign(
    { id: id }, // JWT 데이터
    process.env.REFRESH_TOKEN_SECRET_KEY, // Refresh Token의 비밀 키
    { expiresIn: "7d" } // Refresh Token이 7일 뒤에 만료되도록 설정합니다.
  );

  return refreshToken;
}

/** 엑세스 토큰 검증 API **/
app.get("/tokens/validate", (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res
      .status(400)
      .json({ errorMessage: "Access Token이 존재하지 않습니다." });
  }

  const payload = validateToken(
    accessToken,
    process.env.ACCESS_TOKEN_SECRET_KEY
  );

  if (!payload) {
    return res
      .status(401)
      .json({ errorMessage: "Access Token이 유효하지 않습니다." });
  }

  const { id } = payload;
  return res.json({
    message: `${id}의 Payload를 가진 Token이 성공적으로 인증되었습니다.`,
  });
});

// Token을 검증하고 Payload를 반환합니다.
function validateToken(token, secretKey) {
  try {
    const payload = jwt.verify(token, secretKey);
    return payload;
  } catch (error) {
    return null;
  }
}

/** 리프레시 토큰 검증 API **/
app.post("/tokens/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken)
    return res
      .status(400)
      .json({ errorMessage: "Refresh Token이 존재하지 않습니다." });

  const payload = validateToken(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET_KEY
  );

  if (!payload) {
    return res
      .status(401)
      .json({ errorMessage: "Refresh Token이 유효하지 않습니다." });
  }

  const userInfo = tokenStorage[refreshToken];

  if (!userInfo)
    return res.status(419).json({
      errorMessage: "Refresh Token의 정보가 서버에 존재하지 않습니다.",
    });

  const newAccessToken = createAccessToken(userInfo.id);

  res.cookie("accessToken", newAccessToken);
  return res.json({ message: "Access Token을 새롭게 발급하였습니다." });
});

// Token을 검증하고 Payload를 반환합니다.
function validateToken(token, secretKey) {
  try {
    const payload = jwt.verify(token, secretKey);
    return payload;
  } catch (error) {
    return null;
  }
}

app.listen(PORT, () => {
  console.log(PORT, "포트로 서버가 열렸어요!");
});
