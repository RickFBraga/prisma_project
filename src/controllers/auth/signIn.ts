import { User } from "@prisma/client";
import prisma from "../../database/database";
import { NextFunction, Request, Response } from "express";
import { SignIn } from "protocols";
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

export const signIn = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const { email, password }: SignIn = req.body;

    try {
        const existingUser: User | null = await prisma.user.findUnique({
            where: { email }
        });

        if (!existingUser) {
            return next({ status: 404, message: "Email Not Found" });
        }

        const isPasswordValid = await bcrypt.compare(password, existingUser.password);

        if (!isPasswordValid) {
            return next({ status: 401, message: "Unauthorized" });
        }

        const token = jwt.sign(
            { userId: existingUser.id, email: existingUser.email },
            process.env.JWT_SECRET as string,
            { expiresIn: '1h' }
        );

        res.status(200).json({ token });
    } catch (error) {
        next(error);
    }
};