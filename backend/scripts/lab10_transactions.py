"""MongoDB transaction exercises for bank transfers and inventory reservations."""

import math
import random
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from pymongo.errors import PyMongoError


class InsufficientFundsError(ValueError):
    """Raised when an account cannot fund a transfer."""


class InsufficientStockError(ValueError):
    """Raised when inventory cannot satisfy a reservation."""


def _validate_retry_options(max_attempts, backoff_base):
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    if (
        isinstance(backoff_base, bool)
        or not isinstance(backoff_base, (int, float))
        or not math.isfinite(backoff_base)
        or backoff_base < 0
    ):
        raise ValueError("backoff_base must be a non-negative finite number")


def _run_transaction(client, operation, max_attempts=5, backoff_base=0.1, sleep=time.sleep):
    _validate_retry_options(max_attempts, backoff_base)
    with client.start_session() as session:
        for attempt in range(max_attempts):
            try:
                with session.start_transaction():
                    return operation(session)
            except PyMongoError as error:
                if (
                    not error.has_error_label("TransientTransactionError")
                    or attempt + 1 == max_attempts
                ):
                    raise
                delay = min(backoff_base * (2 ** attempt), 1.0) * random.uniform(
                    0.5, 1.5
                )
                print(
                    f"Transient transaction error; retrying "
                    f"{attempt + 2}/{max_attempts} after {delay:.3f}s."
                )
                sleep(delay)


def transfer(
    accounts,
    history,
    source_id,
    destination_id,
    amount,
    max_attempts=5,
    backoff_base=0.1,
    sleep=time.sleep,
):
    if source_id == destination_id:
        raise ValueError("source_id and destination_id must be different")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("amount must be a positive finite number")
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError("amount must be a positive finite number")

    client = accounts.database.client
    transfer_id = str(uuid.uuid4())

    def apply(session):
        source = accounts.find_one({"account_id": source_id}, session=session)
        if source is None:
            raise ValueError(f"Source account {source_id!r} does not exist")
        if accounts.find_one({"account_id": destination_id}, session=session) is None:
            raise ValueError(f"Destination account {destination_id!r} does not exist")

        debit = accounts.update_one(
            {"account_id": source_id, "balance": {"$gte": amount}},
            {"$inc": {"balance": -amount, "version": 1}},
            session=session,
        )
        if debit.matched_count != 1:
            raise InsufficientFundsError(f"Insufficient funds in account {source_id!r}")
        credit = accounts.update_one(
            {"account_id": destination_id},
            {"$inc": {"balance": amount, "version": 1}},
            session=session,
        )
        if credit.matched_count != 1:
            raise ValueError(f"Destination account {destination_id!r} does not exist")

        history.insert_one(
            {
                "_id": transfer_id,
                "source_id": source_id,
                "destination_id": destination_id,
                "amount": amount,
                "created_at": datetime.now(timezone.utc),
            },
            session=session,
        )
        return transfer_id

    return _run_transaction(
        client, apply, max_attempts=max_attempts, backoff_base=backoff_base, sleep=sleep
    )


def reserve_inventory(
    inventory,
    orders,
    order_id,
    customer_id,
    items,
    max_attempts=5,
    backoff_base=0.1,
    sleep=time.sleep,
):
    if not isinstance(customer_id, str) or not customer_id.strip():
        raise ValueError("customer_id must be a non-empty string")
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list")

    normalized_items = []
    seen_products = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each item must be an object")
        product_id = item.get("product_id")
        quantity = item.get("qty")
        price = item.get("price")
        if not isinstance(product_id, str) or not product_id:
            raise ValueError("Each item must have a non-empty product_id")
        if product_id in seen_products:
            raise ValueError(f"Product {product_id!r} occurs more than once")
        if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 1:
            raise ValueError("Each item qty must be a positive integer")
        if isinstance(price, bool) or not isinstance(price, (int, float)):
            raise ValueError("Each item price must be a non-negative finite number")
        if not math.isfinite(price) or price < 0:
            raise ValueError("Each item price must be a non-negative finite number")
        normalized_items.append(
            {"product_id": product_id, "qty": quantity, "price": float(price)}
        )
        seen_products.add(product_id)

    client = inventory.database.client

    def apply(session):
        for item in sorted(normalized_items, key=lambda row: row["product_id"]):
            product = inventory.find_one(
                {"product_id": item["product_id"]}, session=session
            )
            if product is None:
                raise InsufficientStockError(
                    f"Product {item['product_id']!r} is not in inventory"
                )
            if product.get("stock", 0) < item["qty"]:
                raise InsufficientStockError(
                    f"Insufficient stock for product {item['product_id']!r}"
                )
            result = inventory.update_one(
                {
                    "product_id": item["product_id"],
                    "stock": {"$gte": item["qty"]},
                },
                {"$inc": {"stock": -item["qty"], "version": 1}},
                session=session,
            )
            if result.matched_count != 1:
                raise InsufficientStockError(
                    f"Insufficient stock for product {item['product_id']!r}"
                )

        order = {
            "order_id": order_id,
            "customer_id": customer_id,
            "items": normalized_items,
            "status": "pending",
            "total": sum(row["qty"] * row["price"] for row in normalized_items),
            "created_at": datetime.now(timezone.utc),
        }
        orders.insert_one(order, session=session)
        return order

    return _run_transaction(
        client, apply, max_attempts=max_attempts, backoff_base=backoff_base, sleep=sleep
    )


def run_transfer_demo(database, max_attempts=5, backoff_base=0.1):
    accounts = database["lab10_accounts"]
    history = database["lab10_transfer_history"]
    accounts.drop()
    history.drop()
    accounts.create_index("account_id", unique=True)
    accounts.insert_many(
        [
            {"account_id": "account-001", "balance": 1000.0, "version": 0},
            {"account_id": "account-002", "balance": 500.0, "version": 0},
        ]
    )

    transfer_id = transfer(
        accounts,
        history,
        "account-001",
        "account-002",
        100.0,
        max_attempts=max_attempts,
        backoff_base=backoff_base,
    )
    before_failed_transfer = {
        account_id: accounts.find_one({"account_id": account_id})["balance"]
        for account_id in ("account-001", "account-002")
    }
    insufficient_funds = False
    try:
        transfer(
            accounts,
            history,
            "account-001",
            "account-002",
            10000.0,
            max_attempts=max_attempts,
            backoff_base=backoff_base,
        )
    except InsufficientFundsError as error:
        insufficient_funds = True
        print(f"Expected insufficient-funds rollback: {error}")

    after_failed_transfer = {
        account_id: accounts.find_one({"account_id": account_id})["balance"]
        for account_id in ("account-001", "account-002")
    }
    rollback_verified = (
        insufficient_funds and before_failed_transfer == after_failed_transfer
    )
    if not rollback_verified:
        raise AssertionError("Insufficient-funds transaction did not roll back")
    return {
        "transfer_id": transfer_id,
        "accounts": after_failed_transfer,
        "history_count": history.count_documents({}),
        "insufficient_funds_rejected": insufficient_funds,
        "rollback_verified": rollback_verified,
        "collections": [accounts.name, history.name],
    }


def run_inventory_demo(database, workers=(1, 4, 8, 16), max_attempts=8):
    inventory = database["lab10_inventory"]
    orders = database["lab10_orders"]
    inventory.drop()
    orders.drop()
    inventory.create_index("product_id", unique=True)
    orders.create_index("order_id", unique=True)
    inventory.insert_one(
        {
            "product_id": "lab10-product-001",
            "name": "Transaction test product",
            "stock": 5,
            "version": 0,
        }
    )

    def make_reservation(index):
        return reserve_inventory(
            inventory,
            orders,
            f"contention-order-{index}",
            f"customer-{index}",
            [{"product_id": "lab10-product-001", "qty": 1, "price": 12.5}],
            max_attempts=max_attempts,
            backoff_base=0.1,
        )

    contention = {"succeeded": 0, "insufficient_stock": 0}
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(make_reservation, index) for index in range(8)]
        for future in as_completed(futures):
            try:
                future.result()
                contention["succeeded"] += 1
            except InsufficientStockError:
                contention["insufficient_stock"] += 1

    remaining_stock = inventory.find_one(
        {"product_id": "lab10-product-001"}
    )["stock"]
    order_count = orders.count_documents({})
    if (
        contention["succeeded"] != 5
        or contention["insufficient_stock"] != 3
        or remaining_stock != 0
        or order_count != 5
    ):
        raise AssertionError(
            "Concurrent reservation results did not match stock and order totals"
        )

    benchmark_rows = []
    request_count = 32
    for worker_count in workers:
        benchmark_inventory = database["lab10_inventory_benchmark"]
        benchmark_orders = database["lab10_orders_benchmark"]
        benchmark_inventory.drop()
        benchmark_orders.drop()
        benchmark_inventory.create_index("product_id", unique=True)
        benchmark_orders.create_index("order_id", unique=True)
        requests_per_worker = request_count // worker_count
        benchmark_inventory.insert_many(
            [
                {
                    "product_id": f"benchmark-product-{worker}",
                    "name": "Benchmark product",
                    "stock": requests_per_worker,
                    "version": 0,
                }
                for worker in range(worker_count)
            ]
        )

        def reserve_benchmark_worker(worker):
            product_id = f"benchmark-product-{worker}"
            for index in range(requests_per_worker):
                reserve_inventory(
                    benchmark_inventory,
                    benchmark_orders,
                    f"benchmark-{worker_count}-{worker}-{index}",
                    f"benchmark-customer-{worker}-{index}",
                    [{"product_id": product_id, "qty": 1, "price": 1.0}],
                    max_attempts=max_attempts,
                    backoff_base=0.01,
                )

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(reserve_benchmark_worker, worker)
                for worker in range(worker_count)
            ]
            for future in as_completed(futures):
                future.result()
        elapsed = time.perf_counter() - started
        successes = benchmark_orders.count_documents({})
        benchmark_rows.append(
            {
                "concurrency": worker_count,
                "requests": request_count,
                "successful_reservations": successes,
                "elapsed_seconds": round(elapsed, 6),
                "throughput_per_second": round(successes / elapsed, 3),
            }
        )

    return {
        "contention": {
            **contention,
            "initial_stock": 5,
            "remaining_stock": remaining_stock,
            "created_orders": order_count,
            "rollback_or_stock_invariant_verified": True,
        },
        "throughput": benchmark_rows,
        "throughput_note": (
            "The 32-reservation throughput workload assigns one inventory product "
            "per worker; same-product contention is measured separately above."
        ),
        "collections": [
            inventory.name,
            orders.name,
            "lab10_inventory_benchmark",
            "lab10_orders_benchmark",
        ],
    }
