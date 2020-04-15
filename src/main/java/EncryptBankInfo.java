import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.Binary;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import static com.mongodb.client.model.Filters.eq;

/**
 * https://docs.mongodb.com/ecosystem/use-cases/client-side-field-level-encryption-guide/
 */

public class EncryptBankInfo
{
    private static boolean keyExists;

    private static String connectionString = "mongodb://localhost:27017,localhost:27018,localhost:27019/?replicaSet=csfle";
    private static String keyVaultDatabase = "encryption";
    private static String keyVaultCollection = "__keyVault";
    private static String keyVaultNamespace = keyVaultDatabase.concat(".").concat(keyVaultCollection);
    private static boolean createClientEncryptionKeyNow = false;
    private static boolean verifyCreateClientEncryptionCreated = true;
    private static boolean insertPatient = true;

    /*
        Step 1, set createClientEncryptionKeyNow = true

        Uses the base64 data key id returned by createClientEncryptionKey() in the prior step
    */
    private static String base64KeyId = "vLbAYla+TOiu9v6ewbnUtw==";

    public static void main(final String[] args)
    {
        /*
            Get the master Key or create it
         */
        String path = "master-key.txt";
        byte[] localMasterKey= new byte[96];
        getLocalMasterKey(path, localMasterKey);

        /*
            Will  create a key as follows if required to do so:

            DataKeyId [UUID]: 02e144dd-6180-473a-94d9-3c9a34a39131
            DataKeyId [base64]: AuFE3WGARzqU2TyaNKORMQ==
         */

        String base64ClientEncryptionKeyNow;
        if ( createClientEncryptionKeyNow ) {
            base64ClientEncryptionKeyNow = createClientEncryptionKey(localMasterKey);

        /*
            Verify that the Data Encryption Key was Created
         */
            if (verifyCreateClientEncryptionCreated) {
                MongoClient mongoClient = MongoClients.create(connectionString);
                MongoCollection<Document> collection = mongoClient.getDatabase(keyVaultDatabase).getCollection(keyVaultCollection);

        /*
            This retrieved document contains the following data:

            Data encryption key id (stored as a UUID).
            Data encryption key in encrypted form.
            KMS provider information for the master key.
            Other metadata such as creation and last modified date.
         */
                Bson query = Filters.eq("_id", new Binary((byte) 4, Base64.getDecoder().decode(base64ClientEncryptionKeyNow)));
                Document doc = collection
                        .find(query)
                        .first();

                System.out.println(doc);
                System.out.println("Store the key \n\t1] '" + base64ClientEncryptionKeyNow + "' in the variable base64KeyId" +
                                 " \n\t2] set createClientEncryptionKeyNow = false");
                System.exit(0);
            }
        }

        /*
            A single data key to use when encrypting all fields in the data model.
            To configure this, they specify the encryptMetadata key at the root level of the JSON Schema.
            As a result, all encrypted fields defined in the properties field of the schema will inherit
            this encryption key unless specifically overwritten.


            {
              "bsonType": "object",
              "encryptMetadata": {
                "keyId": [
                  {
                    "$binary": {
                      "base64": "02e144dd-6180-473a-94d9-3c9a34a39131",
                      "subType": "04"
                    }
                  }
                ]
              },
              "properties": {
                "insurance": {
                  "bsonType": "object",
                  "properties": {
                    "policyNumber": {
                      "encrypt": {
                        "bsonType": "int",
                        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                      }
                    }
                  }
                },
                "medicalRecords": {
                  "encrypt": {
                    "bsonType": "array",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                  }
                },
                "bloodType": {
                  "encrypt": {
                    "bsonType": "string",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                  }
                },
                "ssn": {
                  "encrypt": {
                    "bsonType": "int",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                  }
                }
              }
            }

         */

        /*
            Use the following procedure to configure and instantiate the
            CSFLE MongoDB client
         */


        Map<String, Map<String, Object>> kmsProviders = getKmsProvider( localMasterKey  );
        HashMap<String, BsonDocument> schemaMap = new HashMap<String, BsonDocument>();
        Document jsonSchema = createJSONSchema( base64KeyId );
        schemaMap.put("medicalRecords.patients", BsonDocument.parse(jsonSchema.toJson()));

        // Spawn the mongocryptd
        Map<String, Object> extraOptions = new HashMap<String, Object>();
        extraOptions.put("mongocryptdSpawnPath", "/usr/local/bin/mongocryptd");

        // automatic encryption settings
        MongoClientSettings clientSettings = MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(connectionString))
                .autoEncryptionSettings(AutoEncryptionSettings.builder()
                        .keyVaultNamespace(keyVaultNamespace)
                        .kmsProviders(kmsProviders)
                        .schemaMap(schemaMap)
                        .extraOptions(extraOptions)
                        .build())
                .build();

        MongoClient mongoClient = MongoClients.create(clientSettings);
        MongoCollection connection = mongoClient.getDatabase("medicalRecords").getCollection("patients");

        if ( insertPatient )
        {
            ArrayList<Document> medicalRecords = new ArrayList<Document>();
            medicalRecords.add(
                    new Document()
                            .append("weight",180)
                            .append("bloodPressure", "120/80")
            );

            insertPatient(
                    connection,
                    "Norris Chucker",
                    7120986,
                    "O Positive",
                    medicalRecords,
                    9876235,
                    "AXA"
            );
        }

        Document document = findPatient(connection, 7120986);
        System.out.println( document.toJson() );

    }

    private static void getLocalMasterKey(String path, byte[] localMasterKey) {

        // Check if the Local Master Key already exists
        try (FileInputStream fis = new FileInputStream(path)) {
            fis.readNBytes(localMasterKey, 0, 96);
            keyExists = true;
        }
        catch (IOException e) {
            System.out.println("ERROR - getLocalMasterKey() failed");
            e.printStackTrace();
        }


        // This would have to be the same master key as was used to create the encryption key
        if ( ! keyExists ) {
            new SecureRandom().nextBytes(localMasterKey);

            try (FileOutputStream stream = new FileOutputStream("master-key.txt")) {
                stream.write(localMasterKey);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static  Map<String, Map<String, Object>> getKmsProvider( byte[] localMasterKey )
    {
        /*
            The KMS provider settings are stored in a Map in order to use the kmsProviders
            helper method for the ClientEncryptionSettings Builder.
         */
        Map<String, Object> keyMap = new HashMap<String, Object>();
        keyMap.put("key", localMasterKey);

        // Local KMS
        Map<String, Map<String, Object>> kmsProviders = new HashMap<String, Map<String, Object>>();
        kmsProviders.put("local", keyMap);
        return kmsProviders;
    }

    private static String createClientEncryptionKey(byte[] localMasterKey)
    {
        String kmsProvider = "local";

        // Local KMS
        Map<String, Map<String, Object>> kmsProviders = getKmsProvider( localMasterKey  );

        ClientEncryptionSettings clientEncryptionSettings = ClientEncryptionSettings.builder()
                .keyVaultMongoClientSettings(MongoClientSettings.builder()
                        .applyConnectionString(new ConnectionString(connectionString))
                        .build())
                .keyVaultNamespace(keyVaultNamespace)
                .kmsProviders(kmsProviders)
                .build();

        ClientEncryption clientEncryption = ClientEncryptions.create(clientEncryptionSettings);
        BsonBinary dataKeyId = clientEncryption.createDataKey(kmsProvider, new DataKeyOptions());
        System.out.println("DataKeyId [UUID]: " + dataKeyId.asUuid());

        String base64DataKeyId = Base64.getEncoder().encodeToString(dataKeyId.getData());
        System.out.println("DataKeyId [base64]: " + base64DataKeyId);
        return base64DataKeyId;
    }

    public static Document createJSONSchema(String keyId) throws IllegalArgumentException {
        if (keyId.isEmpty()) {
            throw new IllegalArgumentException("keyId must contain your base64 encryption key id.");
        }
        return new Document()
                .append("bsonType", "object")
                .append("encryptMetadata", createEncryptMetadataSchema(keyId))
                .append("properties", new Document()
                        .append("ssn", buildEncryptedField("int", true))
                        .append("bloodType", buildEncryptedField("string", false))
                        .append("medicalRecords", buildEncryptedField("array", false))
                        .append("insurance", new Document()
                                .append("bsonType", "object")
                                .append("properties",
                                        new Document()
                                                .append("policyNumber", buildEncryptedField("int", true)))));
    }


    private static Document createEncryptMetadataSchema(String keyId) {
        /*
                {
                    "keyId": [
                      {
                        "$binary": {
                          "base64": "<paste_your_key_id_here>",
                          "subType": "04"
                        }
                      }
                    ]
                }
         */
        ArrayList<Document> arrayList = new ArrayList<Document>();
        Document payload = new Document()
                .append("$binary", new Document()
                        .append("base64", keyId)
                        .append("subType", 4));
        arrayList.add(payload);

        Document doc = new Document()
                .append("keyId", arrayList);

        return doc;
    }


    public static Document buildEncryptedField(String type, boolean deterministic) {
        /*
                {
                  "encrypt": {
                    "bsonType": "int",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                  }
                }
         */
        String algo = deterministic ? "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic":"AEAD_AES_256_CBC_HMAC_SHA_512-Random";
        Document doc = new Document()
                .append("encrypt", new Document()
                    .append("bsonType", type)
                    .append("algorithm", algo)
        );
        return doc;
    }


    public static void insertPatient(
            MongoCollection collection,
            String name,
            int ssn,
            String bloodType,
            ArrayList<Document> medicalRecords,
            int policyNumber,
            String provider
    ) {

        Document insurance = new Document()
                .append("policyNumber", policyNumber)
                .append("provider", provider);

        Document patient = new Document()
                .append("name", name)
                .append("ssn", ssn)
                .append("bloodType", bloodType)
                .append("medicalRecords", medicalRecords)
                .append("insurance", insurance);

        collection.insertOne(patient);
    }

    public static Document findPatient(  MongoCollection collection, int ssn  ) {
        Document doc = (Document) collection.find(eq("ssn", ssn)).first();
        return doc;
    }
}
