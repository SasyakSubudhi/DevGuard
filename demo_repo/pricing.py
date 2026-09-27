def average_price(prices: list[float]) -> float:
    """Return the average price, or zero when an order has no priced items."""
    if not prices:
        return 0.0
    return sum(prices) / len(prices)
