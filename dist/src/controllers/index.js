"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteCredential = exports.updateCredential = exports.getCredentialById = exports.getAllCredentials = exports.Credentials = exports.signIn = exports.signUp = void 0;
const database_1 = __importDefault(require("../database/database"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const cryptr_1 = __importDefault(require("cryptr"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const encryptedKey = process.env.ENCRYPTION_KEY;
if (!encryptedKey) {
    throw new Error("ENCRYPTION_KEY is not defined in the environment variables");
}
const cryptr = new cryptr_1.default(encryptedKey);
const signUp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, name, password } = req.body;
    try {
        const existingUser = yield database_1.default.user.findUnique({
            where: { email }
        });
        if (existingUser) {
            res.status(409).json({ message: "Conflict" });
            return;
        }
        const hashedPassword = yield bcrypt_1.default.hash(password, 10);
        const newUser = yield database_1.default.user.create({
            data: {
                email,
                name,
                password: hashedPassword
            }
        });
        res.status(201).json(newUser);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.signUp = signUp;
const signIn = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    try {
        const existingUser = yield database_1.default.user.findUnique({
            where: { email }
        });
        if (!existingUser) {
            res.status(404).json({ message: "Email Not Found" });
            return;
        }
        const isPasswordValid = yield bcrypt_1.default.compare(password, existingUser.password);
        if (!isPasswordValid) {
            res.status(401).json({ message: "Unauthorized" });
            return;
        }
        const token = jsonwebtoken_1.default.sign({ userId: existingUser.id, email: existingUser.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.signIn = signIn;
const Credentials = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { password, title, url, username } = req.body;
    try {
        if (req.userId === undefined) {
            res.status(400).json({ message: "User ID is required" });
            return;
        }
        const encryptedPassword = cryptr.encrypt(password);
        const newCredential = yield database_1.default.credential.create({
            data: {
                title,
                url,
                username,
                password: encryptedPassword,
                userId: req.userId
            }
        });
        res.status(201).json(newCredential);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.Credentials = Credentials;
const getAllCredentials = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const credentials = yield database_1.default.credential.findMany({
            where: {
                userId: req.userId
            }
        });
        const decryptedCredentials = credentials.map(credential => (Object.assign(Object.assign({}, credential), { password: cryptr.decrypt(credential.password) })));
        res.status(200).json(decryptedCredentials);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.getAllCredentials = getAllCredentials;
const getCredentialById = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    try {
        const credential = yield database_1.default.credential.findUnique({
            where: {
                id: Number(id),
                userId: req.userId
            }
        });
        if (!credential) {
            res.status(404).json({ message: "Credential Not Found" });
            return;
        }
        const decryptedCredential = Object.assign(Object.assign({}, credential), { password: cryptr.decrypt(credential.password) });
        res.status(200).json(decryptedCredential);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.getCredentialById = getCredentialById;
const updateCredential = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    const { title, url, username, password } = req.body;
    try {
        const existingCredential = yield database_1.default.credential.findUnique({
            where: { id: Number(id) }
        });
        if (!existingCredential) {
            res.status(404).json({ message: "Credential Not Found" });
            return;
        }
        const encryptedPassword = cryptr.encrypt(password);
        yield database_1.default.credential.update({
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
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.updateCredential = updateCredential;
const deleteCredential = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    try {
        const existingCredential = yield database_1.default.credential.findUnique({
            where: { id: Number(id) }
        });
        if (!existingCredential) {
            res.status(404).json({ message: "Credential Not Found" });
            return;
        }
        yield database_1.default.credential.delete({
            where: { id: Number(id) }
        });
        res.status(204).send();
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});
exports.deleteCredential = deleteCredential;
