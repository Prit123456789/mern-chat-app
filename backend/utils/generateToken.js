import jwt from "jsonwebtoken";

/**
 * Generate a JWT token and set it as a cookie in the response.
 *
 * @param {string} userId - The user ID to include in the JWT payload.
 * @param {object} res - The response object from Express.
 */
const generateTokenAndSetCookie = (userId, res) => {
    try {
        // Ensure JWT_SECRET is defined
        if (!process.env.JWT_SECRET) {
            throw new Error("JWT_SECRET is not defined in environment variables");
        }

        // Generate the token
        const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
            expiresIn: "15d", // Token expiry duration
        });

        // Set the token in a secure cookie
        res.cookie("jwt", token, {
            maxAge: 15 * 24 * 60 * 60 * 1000, // 15 days in milliseconds
            httpOnly: true, // Prevents JavaScript access to cookies (mitigates XSS)
            sameSite: "strict", // Prevents CSRF attacks
            secure: process.env.NODE_ENV === "production", // Only send over HTTPS in production
        });
    } catch (error) {
        console.error("Error generating token or setting cookie:", error.message);
        throw new Error("Token generation failed");
    }
};

export default generateTokenAndSetCookie;
