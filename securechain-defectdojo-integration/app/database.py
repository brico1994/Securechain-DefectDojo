from pymongo import MongoClient
from pymongo.collection import Collection
from typing import Optional
import os


class DatabaseManager:
    """
    MongoDB Manager (singleton)

    Responsabilidades:
    - Crear conexión única
    - Exponer DB
    - Exponer colecciones
    """

    _instance: Optional["DatabaseManager"] = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized") and self._initialized:
            return

        self.mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        self.mongo_db_name: str = os.getenv("MONGO_DB_NAME", "securechain")

        try:
            self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
            # Verifica conexión
            self.client.server_info()
        except Exception as e:
            raise RuntimeError(f"MongoDB connection failed: {e}")

        self.db = self.client[self.mongo_db_name]

        self._initialized = True

    def get_db(self):
        return self.db

    def get_collection(self, name: str) -> Collection:
        return self.db[name]

    def get_generic_findings_collection(self) -> Collection:
        """
        Colección específica para Generic Findings
        """
        return self.get_collection("generic_findings_documents")

    def ensure_indexes(self) -> None:
        """
        Crear índices necesarios (idempotente)
        """
        collection = self.get_generic_findings_collection()

        # Índice único por document_id
        collection.create_index("document_id", unique=True)

        # Índice para queries por repository
        collection.create_index("repository_id")

    def health_check(self) -> bool:
        """
        Verifica conexión con Mongo
        """
        try:
            self.client.admin.command("ping")
            return True
        except Exception:
            return False


# Instancia global (opcional)
db_manager = DatabaseManager()
