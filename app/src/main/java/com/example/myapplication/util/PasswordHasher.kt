package com.example.myapplication.util

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Cifra contraseñas con PBKDF2 y una sal aleatoria por usuario, para no guardarlas
 * nunca en texto plano en la base de datos local.
 *
 * Formato almacenado: "iteraciones:salHex:hashHex".
 * Se usa PBKDF2WithHmacSHA1 porque está disponible desde la API 24 (minSdk del proyecto).
 */
object PasswordHasher {

    private const val ALGORITMO = "PBKDF2WithHmacSHA1"
    private const val ITERACIONES = 10_000
    private const val LONGITUD_CLAVE_BITS = 256
    private const val LONGITUD_SAL_BYTES = 16

    fun hash(password: String): String {
        val sal = ByteArray(LONGITUD_SAL_BYTES).also { SecureRandom().nextBytes(it) }
        val hash = derivar(password, sal, ITERACIONES)
        return "$ITERACIONES:${sal.toHex()}:${hash.toHex()}"
    }

    fun verify(password: String, almacenado: String): Boolean {
        val partes = almacenado.split(":")
        if (partes.size != 3) return false
        val iteraciones = partes[0].toIntOrNull() ?: return false
        val sal = partes[1].hexToBytes() ?: return false
        val esperado = partes[2].hexToBytes() ?: return false
        val calculado = derivar(password, sal, iteraciones)
        // Comparación en tiempo constante
        return MessageDigest.isEqual(calculado, esperado)
    }

    private fun derivar(password: String, sal: ByteArray, iteraciones: Int): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), sal, iteraciones, LONGITUD_CLAVE_BITS)
        return try {
            SecretKeyFactory.getInstance(ALGORITMO).generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToBytes(): ByteArray? {
        if (length % 2 != 0) return null
        return try {
            ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        } catch (_: NumberFormatException) {
            null
        }
    }
}
