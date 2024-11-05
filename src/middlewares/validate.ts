import { Request, Response, NextFunction } from 'express';
import { ObjectSchema } from 'joi';
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest } from '../protocols';
import dotenv from 'dotenv'

dotenv.config()

export const validateSchema = (schema: ObjectSchema) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        const { error } = schema.validate(req.body, { abortEarly: false });

        if (error) {
            const errors = error.details.map(detail => detail.message);
            res.status(422).json({ errors });
        } else {
            next();
        }
    };
};

export const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ message: "Unauthorized" });
        return
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { userId: number };
        req.userId = decoded.userId;
        next();
    } catch (error) {
        console.error("Token verification failed:", error);
        res.status(403).json({ message: "Forbidden" });
    }
};

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction): void => {
    console.error("An error occurred:", err);

    if (res.headersSent) {
        return next(err);
    }

    const status = err.status || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
};