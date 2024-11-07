import { User } from "@prisma/client";
import prisma from "../../database/database";
import { NextFunction, Request, Response } from "express";
import { SignUp } from "protocols";
import bcrypt from 'bcrypt'

export const signUp = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const { email, name, password }: SignUp = req.body;

    try {
        const existingUser: User | null = await prisma.user.findUnique({
            where: { email }
        });

        if (existingUser) {
            return next({ status: 409, message: "Conflict" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser: User = await prisma.user.create({
            data: {
                email,
                name,
                password: hashedPassword
            }
        });

        res.status(201).json(newUser);
    } catch (error) {
        next(error);
    }
};
