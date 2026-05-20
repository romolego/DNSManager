"""Тесты атомарного захвата DNS-операции (_try_begin_operation / _end_operation).

Эти методы — единственная точка перехода operation_in_progress в True; именно
они устраняют гонку между автовосстановлением (поток мониторинга) и
пользовательским действием. Сами методы не зависят от Tkinter, поэтому
тестируем их на инстансе, созданном через object.__new__ (без запуска окна).

Модуль dnsmgr.app требует pystray/PIL — если их нет (например, в системном
Python без GUI-зависимостей), тест пропускается.
"""

import threading
import unittest

try:
    from dnsmgr.app import DNSManagerApp
    _HAVE_GUI = True
except Exception:
    _HAVE_GUI = False


@unittest.skipUnless(_HAVE_GUI, "dnsmgr.app требует pystray/PIL")
class OperationLockTest(unittest.TestCase):
    def _make_app(self):
        # Создаём объект без вызова tk.Tk.__init__ — нам нужны только
        # _op_state_lock + operation_in_progress + сами методы.
        app = object.__new__(DNSManagerApp)
        app._op_state_lock = threading.Lock()
        app.operation_in_progress = False
        return app

    def test_begin_end_cycle(self):
        app = self._make_app()
        self.assertTrue(app._try_begin_operation())    # свободно → захватили
        self.assertFalse(app._try_begin_operation())   # уже занято
        self.assertFalse(app._try_begin_operation())   # всё ещё занято
        app._end_operation()
        self.assertTrue(app._try_begin_operation())     # освободили → снова можно

    def test_end_is_idempotent(self):
        app = self._make_app()
        app._try_begin_operation()
        app._end_operation()
        app._end_operation()  # повторное снятие не должно ломать состояние
        self.assertFalse(app.operation_in_progress)
        self.assertTrue(app._try_begin_operation())

    def test_concurrent_single_winner(self):
        # 30 потоков стартуют одновременно — ровно один должен захватить
        # операцию. Это и есть проверка атомарности «проверил → начал».
        app = self._make_app()
        n = 30
        barrier = threading.Barrier(n)
        results = []
        results_lock = threading.Lock()

        def worker():
            barrier.wait()  # синхронный старт всех потоков
            ok = app._try_begin_operation()
            with results_lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sum(1 for r in results if r), 1)   # ровно один победитель
        self.assertEqual(len(results), n)                   # все потоки отчитались


if __name__ == "__main__":
    unittest.main()
