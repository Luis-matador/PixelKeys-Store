package com.example.myapplication.util

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordHasherTest {

    @Test
    fun laContrasenaCorrectaSeVerifica() {
        val almacenado = PasswordHasher.hash("secreta123")
        assertTrue(PasswordHasher.verify("secreta123", almacenado))
    }

    @Test
    fun unaContrasenaIncorrectaNoSeVerifica() {
        val almacenado = PasswordHasher.hash("secreta123")
        assertFalse(PasswordHasher.verify("otra", almacenado))
    }

    @Test
    fun noSeGuardaEnTextoPlano() {
        assertFalse(PasswordHasher.hash("secreta123").contains("secreta123"))
    }

    @Test
    fun cadaHashUsaUnaSalDistinta() {
        assertNotEquals(PasswordHasher.hash("secreta123"), PasswordHasher.hash("secreta123"))
    }

    @Test
    fun unValorMalFormadoNoSeVerifica() {
        assertFalse(PasswordHasher.verify("1234", "1234"))
    }
}
