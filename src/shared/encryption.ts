// Crypto utility functions
async function getKey(password: string): Promise<CryptoKey> {
    const enc = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    )

    // Use a constant salt for derivation since we need to reproduce the same key
    const salt = enc.encode('hono-github-auth-salt')

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}


export async function encrypt(plaintext: string, password: string): Promise<string> {
    const enc = new TextEncoder()
    const key = await getKey(password)

    // Generate a random IV for each encryption
    const iv = crypto.getRandomValues(new Uint8Array(12))

    const encryptedContent = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv
        },
        key,
        enc.encode(plaintext)
    )

    // Combine IV and encrypted content into a single array
    const combined = new Uint8Array(iv.length + new Uint8Array(encryptedContent).length)
    combined.set(iv)
    combined.set(new Uint8Array(encryptedContent), iv.length)

    // Convert to base64 for easy transport
    return btoa(String.fromCharCode(...combined))
}

export async function decrypt(ciphertext: string, password: string): Promise<string> {
    const dec = new TextDecoder()
    const key = await getKey(password)

    // Convert from base64 and extract IV
    const combined = new Uint8Array(
        atob(ciphertext)
            .split('')
            .map(char => char.charCodeAt(0))
    )

    const iv = combined.slice(0, 12)
    const encryptedContent = combined.slice(12)

    const decryptedContent = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv
        },
        key,
        encryptedContent
    )

    return dec.decode(decryptedContent)
}