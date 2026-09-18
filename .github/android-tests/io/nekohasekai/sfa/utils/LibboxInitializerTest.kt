package io.nekohasekai.sfa.utils

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LibboxInitializerTest {
    private fun runStartupTest(block: suspend CoroutineScope.() -> Unit) = runBlocking {
        val applicationScope = CoroutineScope(SupervisorJob())
        try {
            withTimeout(5_000) {
                applicationScope.block()
            }
        } finally {
            applicationScope.cancel()
        }
    }

    @Test
    fun coldServiceStartsWaitForOneSharedSetup() = runStartupTest {
        val setupEntered = CompletableDeferred<Unit>()
        val allowSetup = CompletableDeferred<Unit>()
        val setupCalls = AtomicInteger()
        val basePath = AtomicReference("")
        val initializer = LibboxInitializer(this) {
            setupCalls.incrementAndGet()
            setupEntered.complete(Unit)
            allowSetup.await()
            basePath.set("/data/user/0/io.nekohasekai.sfa/files")
        }

        val serviceStarts = List(16) {
            async(start = CoroutineStart.UNDISPATCHED) {
                initializer.await()
                // CommandServer captures the directory when it is created.
                basePath.get()
            }
        }
        setupEntered.await()
        assertEquals(1, setupCalls.get())
        assertTrue(serviceStarts.all { !it.isCompleted })

        allowSetup.complete(Unit)
        assertEquals(List(16) { "/data/user/0/io.nekohasekai.sfa/files" }, serviceStarts.awaitAll())
        assertEquals(1, setupCalls.get())
    }

    @Test
    fun laterStartsReuseCompletedSetupWithoutSuspending() = runStartupTest {
        val setupCalls = AtomicInteger()
        val initializer = LibboxInitializer(this) {
            setupCalls.incrementAndGet()
        }
        initializer.await()

        val laterStart = async(start = CoroutineStart.UNDISPATCHED) {
            initializer.await()
            "ready"
        }
        assertTrue(laterStart.isCompleted)
        assertEquals("ready", laterStart.await())
        assertEquals(1, setupCalls.get())
    }

    @Test
    fun failedSetupReachesEveryCallerWithoutStartingAServerOrRepeatingSetup() = runStartupTest {
        val setupCalls = AtomicInteger()
        val serverStarts = AtomicInteger()
        val initializer = LibboxInitializer(this) {
            setupCalls.incrementAndGet()
            throw IllegalStateException("external files directory unavailable")
        }

        repeat(3) {
            val failure = runCatching {
                initializer.await()
                serverStarts.incrementAndGet()
            }.exceptionOrNull()
            assertTrue(failure is IllegalStateException)
            assertEquals("external files directory unavailable", failure?.message)
        }
        assertEquals(1, setupCalls.get())
        assertEquals(0, serverStarts.get())
    }

    @Test
    fun cancellingOneWaitingServiceDoesNotCancelApplicationSetup() = runStartupTest {
        val setupEntered = CompletableDeferred<Unit>()
        val allowSetup = CompletableDeferred<Unit>()
        val setupCalls = AtomicInteger()
        val initializer = LibboxInitializer(this) {
            setupCalls.incrementAndGet()
            setupEntered.complete(Unit)
            allowSetup.await()
        }
        val firstStart = async { initializer.await() }
        setupEntered.await()
        firstStart.cancelAndJoin()

        val nextStart = async(start = CoroutineStart.UNDISPATCHED) { initializer.await() }
        assertFalse(nextStart.isCompleted)
        allowSetup.complete(Unit)
        nextStart.await()
        assertEquals(1, setupCalls.get())
    }
}
