import { Request, Response } from "express";
import { AuthenticatedRequest, CredentialsInterface, SignIn, SignUp } from "../protocols";
import { PrismaClient, User, Credential } from "@prisma/client";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Cryptr from "cryptr";
import dotenv from 'dotenv';

dotenv.config();

const prisma = new PrismaClient();
const encryptedKey = process.env.ENCRYPTION_KEY;

if (!encryptedKey) {
    throw new Error("ENCRYPTION_KEY is not defined in the environment variables");
}
const cryptr = new Cryptr(encryptedKey);

export const signUp = async (req: Request, res: Response): Promise<void> => {
    const { email, name, password }: SignUp = req.body;

    try {
        const existingUser: User | null = await prisma.user.findUnique({
            where: { email }
        });

        if (existingUser) {
            res.status(409).json({ message: "Conflict" });
            return;
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
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const signIn = async (req: Request, res: Response): Promise<void> => {
    const { email, password }: SignIn = req.body;

    try {
        const existingUser: User | null = await prisma.user.findUnique({
            where: { email }
        });

        if (!existingUser) {
            res.status(404).json({ message: "Email Not Found" });
            return;
        }

        const isPasswordValid = await bcrypt.compare(password, existingUser.password);

        if (!isPasswordValid) {
            res.status(401).json({ message: "Unauthorized" });
            return;
        }

        const token = jwt.sign(
            { userId: existingUser.id, email: existingUser.email },
            process.env.JWT_SECRET as string,
            { expiresIn: '1h' }
        );

        res.status(200).json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const Credentials = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { password, title, url, username }: CredentialsInterface = req.body;

    try {
        if (req.userId === undefined) {
            res.status(400).json({ message: "User ID is required" });
            return;
        }

        const encryptedPassword = cryptr.encrypt(password);

        const newCredential: Credential = await prisma.credential.create({
            data: {
                title,
                url,
                username,
                password: encryptedPassword,
                userId: req.userId
            }
        });

        res.status(201).json(newCredential);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const getAllCredentials = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const credentials: Credential[] = await prisma.credential.findMany({
            where: {
                userId: req.userId
            }
        });

        const decryptedCredentials = credentials.map(credential => ({
            ...credential,
            password: cryptr.decrypt(credential.password)
        }));

        res.status(200).json(decryptedCredentials);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const getCredentialById = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { id } = req.params;

    try {
        const credential: Credential | null = await prisma.credential.findUnique({
            where: {
                id: Number(id),
                userId: req.userId
            }
        });

        if (!credential) {
            res.status(404).json({ message: "Credential Not Found" });
            return;
        }

        const decryptedCredential = {
            ...credential,
            password: cryptr.decrypt(credential.password)
        };

        res.status(200).json(decryptedCredential);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const updateCredential = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { id } = req.params;
    const { title, url, username, password }: CredentialsInterface = req.body;

    try {
        const existingCredential: Credential | null = await prisma.credential.findUnique({
            where: { id: Number(id) }
        });

        if (!existingCredential) {
            res.status(404).json({ message: "Credential Not Found" });
            return;
        }

        const encryptedPassword = cryptr.encrypt(password);

        await prisma.credential.update({
            where: { id: Number(id) },
            data: {
                title,
                url,
                username,
                password: encryptedPassword,
                userId: req.userId
            }
        });

        res.status(204).send();
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const deleteCredential = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { id } = req.params;

    try {
        const existingCredential: Credential | null = await prisma.credential.findUnique({
            where: { id: Number(id) }
        });

        if (!existingCredential) {
            res.status(404).json({ message: "Credential Not Found" });
            return;
        }

        await prisma.credential.delete({
            where: { id: Number(id) }
        });

        res.status(204).send();
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const eraseAllCredentials = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        if (!req.userId) {
            res.status(400).json({ message: "User ID is required" });
            return;
        }

        await prisma.credential.deleteMany({
            where: {
                userId: req.userId
            }
        });

        res.status(204).send();
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

