import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
    const existingUser = await prisma.user.findUnique({
        where: { email: "demo@driven.com.br" },
    });

    if (!existingUser) {
        const hashedPassword = await bcrypt.hash("demo123", 10);

        await prisma.user.create({
            data: {
                name: "Demo",
                email: "demo@driven.com.br",
                password: hashedPassword,
            },
        });

        console.log("Usuário de demonstração criado!");
    } else {
        console.log("Usuário de demonstração já existe.");
    }
}

main()
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
