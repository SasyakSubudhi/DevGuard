from pricing import average_price


def summarize_order(order_id: str, items: list[dict]) -> dict:
    prices = [float(item["price"]) for item in items if item.get("price") is not None]
    return {
        "order_id": order_id,
        "item_count": len(items),
        "average_price": average_price(prices),
    }

