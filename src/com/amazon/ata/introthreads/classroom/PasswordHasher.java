package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A class to pre-compute hashes for all common passwords to speed up cracking the hacked database.
 *
 * Passwords are downloaded from https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
 */
public class PasswordHasher {
    // should create the file in your workspace directory
    private static final String PASSWORDS_AND_HASHES_FILE = "./passwordsAndHashesOutput.csv";


    private static final String DISCOVERED_SALT = "salt";

    /**
     * Generates hashes for all of the given passwords.
     *
     * @param passwords List of passwords to hash
     * @return map of password to hash
     * @throws InterruptedException
     */
    public static Map<String, String> generateAllHashes(List<String> passwords) throws InterruptedException {


        Map<String, String> passwordToHashes = Maps.newConcurrentMap();

     /*   BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwords, DISCOVERED_SALT);*/
    /*    batchHasher.hashPasswords();
        passwordToHashes.putAll(batchHasher.getPasswordToHashes());
*/
        List<List<String>> passwordSublists = Lists.partition(passwords,passwords.size()/4);


        List<BatchPasswordHasher> savedHasher = new ArrayList<>();

        List<Thread> theThreads = new ArrayList<>();


        for(int i = 0; i <passwordSublists.size(); i++){
            BatchPasswordHasher aHasher = new BatchPasswordHasher(passwordSublists.get(i), DISCOVERED_SALT);
            savedHasher.add(aHasher);

            Thread aThread = new Thread(aHasher);

            theThreads.add(aThread);

            aThread.start();
        }

        waitForThreadsToComplete(theThreads);

        for(BatchPasswordHasher aHasher : savedHasher){
            passwordToHashes.putAll(aHasher.getPasswordToHashes());
        }
        return passwordToHashes;
    }

    /**
     * Makes the thread calling this method wait until passed in threads are done executing before proceeding.
     *
     * @param threads to wait on
     * @throws InterruptedException
     */
    public static void waitForThreadsToComplete(List<Thread> threads) throws InterruptedException {
        for (Thread thread : threads) {
            thread.join();
        }
    }

    /**
     * Writes pairs of password and its hash to a file.
     */
    static void writePasswordsAndHashes(Map<String, String> passwordToHashes) {
        File file = new File(PASSWORDS_AND_HASHES_FILE);
        try (
            BufferedWriter writer = Files.newBufferedWriter(file.toPath());
            CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT)
        ) {
            for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
                final String password = passwordToHash.getKey();
                final String hash = passwordToHash.getValue();

                csvPrinter.printRecord(password, hash);
            }
            System.out.println("Wrote output of batch hashing to " + file.getAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
