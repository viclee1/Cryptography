class Decrypt:
    
    OFFSETS = {"balance": 2, "transfer": 5, "invoice": 4}
    patterns = [
                ("balance", "transfer", "invoice"),
                ("balance", "invoice", "transfer"),
                ("transfer", "balance", "invoice"),
                ("transfer", "invoice", "balance"),
                ("invoice", "balance", "transfer"),
                ("invoice", "transfer", "balance"),
                ]

    def __init__(self, ciphertext) -> None:
        self.stream = []
        with open(ciphertext, "rb") as file:
            while True:
                data = file.read(16)
                if not data:
                    break
                self.stream.append(data.hex())

    def get_stream(self):
        return self.stream
    
    def __process_pattern(self, pattern):
        known = {"balance": None, "transfer": None, "invoice": None}
        known[pattern[0]] = self.stream[0]
        i = self.OFFSETS[pattern[0]]

        while i < len(self.stream):
            hex = self.stream[i]
            for type in pattern:
                if known[type] is None:
                    known[type] = hex
                    break
                elif known[type] == hex:
                    i += self.OFFSETS[type]
                    break
            else:
                return None

        if i == len(self.stream):
            return known
        else:
            return None

    def process(self):
        for pattern in self.patterns:
            if (result := self.__process_pattern(pattern)) is not None:
                return result
        return None

    def print_stream(self, transactions):
        for i in range(len(self.stream)):
            for type, value in transactions.items():
                if self.stream[i] == value:
                    print(type.upper())
                    i += self.OFFSETS[type]
                    break

    def get_accounts(self, transactions):
        accounts = {}
        def add_account(acc):
            if acc in accounts:
                accounts[acc] += 1
            else:
                accounts[acc] = 1

        for i in range(len(self.stream)):
            for type, value in transactions.items():
                if self.stream[i] == value:
                    add_account(self.stream[i + 1])
                    if type != "balance":
                        add_account(self.stream[i + 2])
                    i += self.OFFSETS[type]
                    break

        return accounts