package io.nekohasekai.sfa.compose.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlTestProgressTest {
    private fun node(tag: String, id: Long = 0, state: Int = UrlTestState.IDLE, delay: Int = 123) =
        GroupItem(tag, "test", "Test", 1, delay, id, state)

    private fun group(tag: String, items: List<GroupItem>, id: Long = 0, running: Boolean = false) =
        Group(tag, "selector", "Selector", true, items.first().tag, true, items, id, running)

    @Test
    fun startingHidesEveryOldNumberIncludingQueuedAndNestedNodes() {
        val initial = listOf(
            group("all", listOf(node("nested"), node("last"))),
            group("nested", (1..21).map { node("node-$it") }),
        )
        val pending = urlTestBaselines(initial, "all")
        val visible = displayUrlTestProgress(initial, pending)
        assertTrue(visible.all { it.urlTestRunning })
        assertTrue(visible.flatMap { it.items }.all { it.urlTestDelay == 0 && it.urlTestState == UrlTestState.QUEUED })
        assertEquals(123, initial.last().items.last().urlTestDelay)
    }

    @Test
    fun staleSnapshotCannotRestoreOldNumbersAfterClick() {
        val old = listOf(group("all", listOf(node("a", 7), node("b", 7)), 7))
        val pending = urlTestBaselines(old, "all")
        val stillPending = pendingUrlTests(old, pending)
        assertEquals(pending, stillPending)
        assertTrue(displayUrlTestProgress(old, stillPending).single().items.all { it.isTesting })
    }

    @Test
    fun refreshedNumberDoesNotFinishTheBatch() {
        val old = listOf(group("all", listOf(node("a"), node("b"))))
        val update = listOf(group("all", listOf(node("a", 1, UrlTestState.SUCCEEDED, 42), node("b", 1, UrlTestState.RUNNING, 0)), 1, true))
        val pending = pendingUrlTests(update, urlTestBaselines(old, "all"))
        val visible = displayUrlTestProgress(update, pending).single()
        assertEquals(42, visible.items.first().urlTestDelay)
        assertTrue(visible.items.last().isTesting)
        assertTrue(visible.urlTestRunning)
    }

    @Test
    fun coalescedCompletionAcknowledgesFastSuccessAndFailure() {
        val old = listOf(group("all", listOf(node("a"), node("b"))))
        val completed = listOf(group("all", listOf(node("a", 1, UrlTestState.SUCCEEDED, 0), node("b", 1, UrlTestState.FAILED, 0)), 1))
        val pending = pendingUrlTests(completed, urlTestBaselines(old, "all"))
        assertTrue(pending.isEmpty())
        val visible = displayUrlTestProgress(completed, pending).single()
        assertFalse(visible.urlTestRunning)
        assertEquals(UrlTestState.SUCCEEDED, visible.items.first().urlTestState)
        assertEquals(UrlTestState.FAILED, visible.items.last().urlTestState)
    }

    @Test
    fun individualTestHidesEveryCopyOfTheNode() {
        val old = listOf(group("first", listOf(node("shared"))), group("second", listOf(node("shared"))))
        val visible = displayUrlTestProgress(old, urlTestBaselines(old, "shared"))
        assertTrue(visible.all { it.items.single().isTesting })
        assertTrue(visible.none { it.urlTestRunning })
    }

    @Test
    fun olderRemoteCoreDoesNotLeaveOptimisticProgressStuck() {
        val old = listOf(group("all", listOf(node("a"))).copy(urlTestProgressSupported = false))
        assertTrue(urlTestBaselines(old, "all").isEmpty())
    }

    @Test
    fun removingGroupClearsItsPendingRequests() {
        val old = listOf(group("all", listOf(node("a"))))
        assertTrue(pendingUrlTests(emptyList(), urlTestBaselines(old, "all")).isEmpty())
    }
}
