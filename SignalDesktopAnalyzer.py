"""Autopsy add-on module for analyzing Signal Desktop data.

- Built from templates: 
  (1) https://github.com/sleuthkit/autopsy/blob/develop/pythonExamples/Aug2015DataSourceTutorial/FindContactsDb.py
  (2) https://github.com/sleuthkit/autopsy/blob/develop/pythonExamples/Aug2015DataSourceTutorial/RunExe.py
  with permission From author (Brian Carrier).
- Written in Jython.

Classes:
    SignalDesktopAnazerIngestModuleFactory
    SignalDesktopAnalyzerIngestModule
"""
from java.lang import Class
from java.io import File
from java.util.logging import Level
from java.sql  import DriverManager, SQLException

from org.sleuthkit.datamodel import Account
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel.blackboardutils import CommunicationArtifactsHelper
	
import inspect
import os
import json
from subprocess import Popen, PIPE

import decryptor
import parser


class SignalDesktopAnalyzerIngestModuleFactory(IngestModuleFactoryAdapter):
    """Creates instances of SignalDesktopAnalyzerIngestModule and provides general information about the module."""

    moduleName = "Signal Desktop Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses Signal Desktop data artifacts including contacts, messages, and call logs."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return SignalDesktopAnalyzerIngestModule()


class SignalDesktopAnalyzerIngestModule(DataSourceIngestModule):
    """Gets created per data source to do the processing."""

    _logger = Logger.getLogger(SignalDesktopAnalyzerIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    def startUp(self, context):
        self.context = context
        # Verify the executable is in the same folder as the add-on module
        self.pathToEXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fix_schema.exe")
        if not File(self.pathToEXE).exists():
            raise IngestModuleException("EXE was not found in module folder")

    
    # Analyzes the data source
    def process(self, dataSource, progressBar):

        accountOwnerInfo = {"phoneNumber": "", "profileName": ""}
        contactsDict = {}
        moduleName = SignalDesktopAnalyzerIngestModuleFactory.moduleName
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        tempDir = Case.getCurrentCase().getTempDirectory()

        # fix_schema executable only runs on Windows so stop if platform is not Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Stopped processing. Platform is not Windows.")
            return IngestModule.ProcessResult.OK

        # Post a message to the user 
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                                "SignalDesktopAnalyzer ", 
                                                "Started Signal data processing..")
        IngestServices.getInstance().postMessage(message)

        # Initialize progree bar
        progressBar.switchToIndeterminate()

        # Searches for files necessary for the analysis in the data source
        try:
            # Find any file named "config.json" with the parent "Signal"
            keyFiles = fileManager.findFiles(dataSource, "config.json", "Signal")
            # Find any file named "db.sqlite" with the parent "sql" 
            dbFiles = fileManager.findFiles(dataSource, "db.sqlite", "sql")
            # Find any file named "db.sqlite-shm" with the parent "sql" 
            shmFiles = fileManager.findFiles(dataSource, "db.sqlite-shm", "sql")
            # Find any file named "db.sqlite-wal" with the parent "sql"
            walFiles = fileManager.findFiles(dataSource, "db.sqlite-wal", "sql")
        except:
            self.log(Level.INFO, "Error occured while locating Signal files.")
            return IngestModule.ProcessResult.OK

        # Show progress bar
        progressBar.switchToDeterminate(4)

        # Process key file
        try:
            for keyFile in keyFiles:

                # Write a copy of the key file to the temp directory of the current case
                path = os.path.join(tempDir, str(keyFile.getId()) + ".json")
                ContentUtils.writeToFile(keyFile, File(path))
                # Read key value
                keyFileHandler = open(path)
                keyFileContent = json.load(keyFileHandler)
                key = keyFileContent["key"]
                keyFileHandler.close()
                # Only process the first key file
                break
            
        except:
            self.log(Level.INFO, "Error occured while processing key file.")
            return IngestModule.ProcessResult.OK
         
        # Process database file
        for dbFile in dbFiles:
            
            # Write a copy of the database to the temp directory of the current case
            pathToDB = os.path.join(tempDir, str(dbFile.getId()) + ".sqlite") 
            pathToDecryptedDB = os.path.join(tempDir, str(dbFile.getId()) + "_decrypted.sqlite") 
            ContentUtils.writeToFile(dbFile, File(pathToDB))

            # Write a copy of SHM file to the temp directory of the current case
            try:
                for shmFile in shmFiles:
                    pathToSHM = pathToDB + "-shm"
                    ContentUtils.writeToFile(shmFile, File(pathToSHM))
            except:
                self.log(Level.INFO, "Error occured while processing SHM file.")
                return IngestModule.ProcessResult.OK

            # Process WAL file
            try:
                for walFile in walFiles:

                    # Write a copy of WAL file to the temp directory of the current case
                    pathToWAL = pathToDB + "-wal"
                    ContentUtils.writeToFile(walFile, File(pathToWAL))

                    # Decrypt WAL file to be used in deleted messages recovery
                    pathToDecryptedWAL = os.path.join(tempDir, str(walFile.getId()) + "_DecryptedWal.sqlite-wal")
                    decryptor.decryptWAL(key, pathToWAL, pathToDecryptedWAL, doChecksum = False)

            except:
                self.log(Level.INFO, "Error occured while processing WAL file.")
                return IngestModule.ProcessResult.OK

            # Update progress bar
            progressBar.progress(1) 

            # Commit WAL contents to the database
            try: 
                # Create database connection
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % pathToDB)
                self.log(Level.INFO, "Connection to the encrypted database opened.")
                stmt = dbConn.createStatement()
                # Dummy query executed just to commit the changes in WAL to the database 
                # Casues an expected exception
                resultSet = stmt.executeQuery("PRAGMA user_version;") 
            except:
                # Catch the exception and close the database connection to clean up the temporary files
                if stmt:
                    stmt.close()
                if dbConn:
                    dbConn.close()
                    self.log(Level.INFO, "Connection to the encrypted database closed.")

            # Decrypt and store the database
            decryptor.decryptDB(key, pathToDB, pathToDecryptedDB)

            # Post a message to the user showing the path the decrypted database was stored at
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                                  "SignalDesktopAnalyzer ", 
                                                  "Decrypted database stored at " + pathToDecryptedDB )
            IngestServices.getInstance().postMessage(message)

            # Update progress bar
            progressBar.progress(2) 

            # Downgrade sqlite to 3.25 syntax
            # run the executable with the DB file path as input
            exeProcess = Popen([self.pathToEXE, pathToDecryptedDB], stdout=PIPE, stderr=PIPE)    
            processOutput = exeProcess.communicate()[0]

            if "Error" in processOutput.decode():
                self.log(Level.INFO, "Error occured while fixing the database schema: %s" % processOutput.decode())
                return IngestModule.ProcessResult.OK

            try: 
                # Create database connection
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % pathToDecryptedDB)
                stmt = dbConn.createStatement()
            except:
                self.log(Level.INFO, "Error occured while connecting to the decrypted database.")
                return IngestModule.ProcessResult.OK

            # Get suspect's Signal info
            try:
                accountOwnerInfo = parser.parseAccountOwnerInfo(stmt)
                # Create communications helper object to be used to create communication artifacts
                helper = CommunicationArtifactsHelper(Case.getCurrentCaseThrows().getSleuthkitCase(),
                                                            moduleName, 
                                                            dbFile,
                                                            Account.Type.DEVICE,
                                                            Account.Type.DEVICE,
                                                            accountOwnerInfo["profileName"])
            except SQLException as e:
                stmt.close()
                dbConn.close()
                self.log(Level.INFO, "Error occured while getting account owner info. " + e.getMessage())
                return IngestModule.ProcessResult.OK
                    
            try: 
                contactsDict = parser.parseContacts(stmt, helper, accountOwnerInfo)
            except:
                stmt.close()
                dbConn.close()
                self.log(Level.INFO, "Error occured while parsing contacts.")
                return IngestModule.ProcessResult.OK

            try:
                parser.parseMessages(stmt, dataSource, accountOwnerInfo, contactsDict, helper, moduleName)          
            except:
                stmt.close()
                dbConn.close()
                self.log(Level.INFO, "Error occured while parsing messages.")
                return IngestModule.ProcessResult.OK

            try:
                parser.parseCalls(stmt, accountOwnerInfo, contactsDict, helper, moduleName)
            except:
                stmt.close()
                dbConn.close()
                self.log(Level.INFO, "Error occured while parsing calls.")
                return IngestModule.ProcessResult.OK
                    
            # Clean up
            if stmt:
                stmt.close()
            if dbConn:
                dbConn.close()

            # Only process the first database
            break

        # Update progress bar    
        progressBar.progress(3) 

        # Recover deleted messages form WAL file
        try:
            for walFile in walFiles:
                pathToDecryptedWAL = os.path.join(tempDir, str(walFile.getId()) + "_DecryptedWal.sqlite-wal")
                parser.parseDeletedMsgs(pathToDecryptedWAL, walFile, contactsDict, accountOwnerInfo, moduleName)
                # Only process the first WAL file
                break
        except:
            self.log(Level.INFO, "Error occured while recovering deleted messages.")
            return IngestModule.ProcessResult.OK
            
        # Update progress bar    
        progressBar.progress(4) 

        self.log(Level.INFO, "SignalDesktopAnalyzer: Finished processing without errors.")

        # Post a message to the user
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                                "SignalDesktopAnalyzer ", 
                                                "Finished processing without errors.")
        IngestServices.getInstance().postMessage(message)  
        
        return IngestModule.ProcessResult.OK