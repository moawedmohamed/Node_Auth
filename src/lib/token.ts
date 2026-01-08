import jwt from "jsonwebtoken";
export const createAccessToken = (userId: string, role: string, tokenVersion: number, limited?: boolean | undefined) => {
    const payload: any = { sub: userId, role, tokenVersion };
    if (limited)
        payload.limited = true;
    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, { expiresIn: "30m" });

}

export const createRefreshToken = (userId: string, tokenVersion: number) => {
    const payload = { sub: userId, tokenVersion };
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, { expiresIn: "7d" });
}
export const verifyRefreshHandler = (token: string) => {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
        sub: string; tokenVersion: number
    };
} 