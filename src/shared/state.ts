import { HTTPException } from 'hono/http-exception'
import { encrypt, decrypt } from './encryption'

interface State {
    value: string
    expires: number
}

const DEFAULT_VALIDITY_PERIOD = 5 * 60 * 1000 // 5 minutes

export const encodeState = async (value: string, password: string, expires = Date.now() + DEFAULT_VALIDITY_PERIOD) => {
    const state: State = { value, expires }
    return encrypt(JSON.stringify(state), password)
}

export const tryDecodeState = async (encryptedState: string, password: string): Promise<string> => {
    try {
        const state: State = JSON.parse(await decrypt(encryptedState, password))
        if (Date.now() > state.expires) {
            throw new HTTPException(400, { message: 'State is expired' })
        }
        return state.value
    } catch (err) {
        throw new HTTPException(400, { message: 'State is invalid' })
    }
}