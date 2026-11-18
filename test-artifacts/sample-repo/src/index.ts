// Simple TypeScript file for testing
export function hello(name: string): string {
    return `Hello, ${name}!`;
}

export class Greeter {
    constructor(private greeting: string) {}

    greet(name: string): string {
        return `${this.greeting}, ${name}!`;
    }
}

export interface User {
    id: number;
    name: string;
    email: string;
}

export const users: User[] = [
    { id: 1, name: 'Alice', email: 'alice@example.com' },
    { id: 2, name: 'Bob', email: 'bob@example.com' },
];