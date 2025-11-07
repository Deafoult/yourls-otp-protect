<?php

/**
 * Manages a collection of objects in an array with serialization capabilities.
 */
class DataStore implements \IteratorAggregate {
    private array $storage = [];

    // --- CRUD Operations ---

    /**
     * Adds a new object to the store.
     * The object contains an ID and an OTP URL.
     *
     * @param string $id The ID of the object.
     * @param string $otpUrl The OTP URL for the object.
     * @return object The added object.
     */
    public function addObject(string $id, string $otpUrl): object {
        $newObject = (object) [
            'id' => $id,
            'otp_url' => $otpUrl
        ];
        $this->storage[] = $newObject;
        return $newObject;
    }

    /**
     * Deletes an object from the store by its ID.
     *
     * @param string $id The ID of the object to delete.
     * @return bool True on success, false if the object was not found.
     */
    public function deleteObject(string $id): bool {
        foreach ($this->storage as $key => $object) {
            if ($object->id === $id) {
                unset($this->storage[$key]);
                $this->storage = array_values($this->storage); // Re-index the array.
                return true;
            }
        }
        return false;
    }

    /**
     * Returns all objects in the store.
     *
     * @return array An array of all stored objects.
     */
    public function getAllObjects(): array {
        return $this->storage;
    }

    /**
     * Returns an iterator for the stored objects.
     * This allows the DataStore to be used in a foreach loop.
     *
     * @return \Traversable An iterator for the stored objects.
     */
    public function getIterator(): \Traversable {
        return new \ArrayIterator($this->storage);
    }

    // --- Serialization ---

    /**
     * Serializes the current DataStore instance into a string.
     *
     * @return string The serialized string representing the object's state.
     */
    public function serializeData(): string {
        return serialize($this);
    }

    /**
     * Deserializes a string into a new DataStore instance.
     *
     * @param string $serializedString The serialized string.
     * @return DataStore|null The reconstructed DataStore instance or null on failure.
     */
    public static function unserializeData(string $serializedString): ?DataStore {
        $loadedObject = unserialize($serializedString);

        if ($loadedObject instanceof DataStore) {
            return $loadedObject;
        }
        return null;
    }
}