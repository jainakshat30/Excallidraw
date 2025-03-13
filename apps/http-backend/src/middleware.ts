import { NextFunction, Request, Response } from "express";
import jwt, { decode, JwtPayload } from "jsonwebtoken"
import { JWT_SECRET } from "./config";

interface CustomRequest extends Request {
    userId?: string;
}


export function middleware(req:Request, res:Response, next:NextFunction) {
    const token = req.headers["authorization"] ?? "";
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload; // Ensure it's an object

        if (decoded && typeof decoded === "object" && "userId" in decoded) {
            req.userId = decoded.userId as string; // Explicitly assign userId
            next();
        }else{
        res.status(403).json({
            message:"Unauthorized"
        })
    }

}