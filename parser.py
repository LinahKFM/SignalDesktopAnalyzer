"""Parsers forensic artifacts in Signal Desktop SQLite database and its temporary WAL file.

- This module is part of SignalDesktopAnalyzer add-on ingest module for Autopsy.
- Written in Jython.

Functions:
    parseAccountOwnerInfo(object) -> dict
    parseContacts(object, object, dict) -> dict
    parseMessages(object, object, dict, dict, object, str)
    parseCalls(object, dict, dict, object, str)
    parseDeletedMsgs(str, file, dict, dict, str):

"""

import java.util.ArrayList as ArrayList
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper import MessageReadStatus
from org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper import CommunicationDirection
from org.sleuthkit.datamodel.blackboardutils.attributes import MessageAttachments
from org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments import FileAttachment
from org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper import CallMediaType

import json
import os


def parseAccountOwnerInfo(stmt):
    """Retrieves phone number and profile name of Signal account owner.

    Args:
        stmt (object of 'org.sqlite.jdbc4.JDBC4Statement'): A database statement used to execute queries. 

    Returns:
        accountOwnerInfo (dict): A dictionary that stores the retrieved account owner info.
    """

    accountOwnerInfo = {"phoneNumber": "", "profileName": ""}

    # Get phone number of the account owner
    query = """SELECT json 
                FROM  items
                WHERE id IS "accountE164"
            """
    resultSet = stmt.executeQuery(query)

    jsonString = resultSet.getString("json")
    jsonData = json.loads(jsonString)
    accountOwnerInfo["phoneNumber"] = jsonData["value"]

    # Get profile name of the account owner
    query = """SELECT profileFullName
                FROM  conversations
                WHERE e164 IS "%s" 
            """ % accountOwnerInfo["phoneNumber"]
    resultSet = stmt.executeQuery(query)
    accountOwnerInfo["profileName"] = resultSet.getString("profileFullName") + " (Account Owner)"

    return accountOwnerInfo


def parseContacts(stmt, helper, accountOwnerInfo):
    """Retrieves contacts that Signal account owner has communicated with and posts them in Autopsy's Blackboard.

    Args:
        stmt (object of 'org.sqlite.jdbc4.JDBC4Statement'): A database statement used to execute queries. 
        helper (object of 'org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper'): Used to post contacts to the blackboard.
        accountOwnerInfo (dict): A dictionary of account owner info, including phone number and profile name.

    Returns:
        contactsDict (dict): A dictionary that stores contacts information as follows:
                            {"conversation_id_1": "profile_name_1",
                             "uuid_1": "profile_name_1",
                             "phone_number_1": "profile_name_1",
                             "conversation_id_2": "profile_name_2",
                             "uuid_2": "profile_name_2",..}
    """

    contactsDict = {}

    query = """SELECT id,
                      name AS "groupName",
                      profileFullName, 
                      e164 AS "phoneNumber",
                      uuid
                FROM  conversations
            """
    resultSet = stmt.executeQuery(query)

    # Cycle through each row
    while resultSet.next():

            conversationId = resultSet.getString("id")
            groupName = resultSet.getString("groupName")
            profileName = resultSet.getString("profileFullName")
            phoneNumber = resultSet.getString("phoneNumber")
            uuId = resultSet.getString("uuid")

            if str(phoneNumber) == accountOwnerInfo["phoneNumber"]:
                profileName = accountOwnerInfo["profileName"]

            if profileName:
                # Post contact artifact
                helper.addContact(profileName, 
                                  phoneNumber, 
                                  "", 
                                  "", 
                                  "")
                # Store contacts info in a dictionary to be used by other functions
                contactsDict[conversationId] = profileName
                contactsDict[uuId] = profileName
                contactsDict[phoneNumber] = profileName

            if groupName:
                # Store group info in a dictionary to be used by other functions
                contactsDict[conversationId] = "Group: " + str(groupName)

    return contactsDict


def parseMessages(stmt, dataSource, accountOwnerInfo, contactsDict, helper, moduleName):
    """Retrieves messages sent or received on Signal account and posts them in Autopsy's Blackboard.

    Args:
        stmt (object of 'org.sqlite.jdbc4.JDBC4Statement'): A database statement used to execute queries. 
        dataSource (object of 'org.sleuthkit.datamodel.LocalFilesDataSource'): Links to the current data source.
        accountOwnerInfo (dict): A dictionary of account owner info, including phone number and profile name.
        contactsDict (dict): A dictionary that stores contacts information.
        helper (object of 'org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper'): Used to post messages to the blackboard.
        moduleName (str): Name of the ingest module 'SignalDesktopAnalyzer'
    """
    currentCase = Case.getCurrentCase().getSleuthkitCase()
    fileManager = Case.getCurrentCase().getServices().getFileManager()
    additionalAttributes = ArrayList()

    query = """SELECT messages.body,
                      messages.type AS "messageType",
                      messages.conversationId,
                      messages.hasAttachments, 
                      messages.seenStatus,
                      messages.isErased,
                      messages.json,
                      conversations.type AS "conversationType",
                      conversations.name AS "groupName",
                      conversations.e164 AS "phoneNumber"
                FROM  messages
                INNER JOIN conversations ON messages.conversationId = conversations.id
                WHERE messages.type IN ("incoming", "outgoing")
                ORDER BY rowid ASC
            """
    resultSet = stmt.executeQuery(query)
 
    # Create custome artifact attributes
    quoteAtt = currentCase.addArtifactAttributeType("SIGNAL_QUOTED_MSG",
                                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                    "Quoted Message")
        
    readAtt = currentCase.addArtifactAttributeType("SIGNAL_MSG_READ",
                                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                    "Read By")

    # Cycle through each row and create artifacts
    while resultSet.next():
        
        body  = resultSet.getString("body")
        messageType = resultSet.getString("messageType")
        hasAttachments = resultSet.getInt("hasAttachments")
        jsonString = resultSet.getString("json")
        jsonData = json.loads(jsonString)
        timestamp = jsonData["timestamp"] / 1000
        conversationId = resultSet.getString("conversationId")
        seenStatus = resultSet.getString("seenStatus")
        isErased = resultSet.getInt("isErased")
        conversationType = resultSet.getString("conversationType")
        phoneNumber = ""
        sender = ""
        recipient = ""
        quotedMessage = ""
        readByString = ""
        fileAttachments = ArrayList()
        stickers = ArrayList()

        # Get private messages communication details
        if str(conversationType) == "private":
            phoneNumber = resultSet.getString("phoneNumber")
            if str(messageType) == "incoming":
                direction = CommunicationDirection.INCOMING
                sender = contactsDict[phoneNumber]
                recipient = accountOwnerInfo["profileName"]
            else:
                direction = CommunicationDirection.OUTGOING
                sender = accountOwnerInfo["profileName"]
                recipient = contactsDict[phoneNumber]

        # Get group messages communication details
        else:
            groupName = "Group: " + resultSet.getString("groupName")
            if str(messageType) == "incoming":
                direction = CommunicationDirection.INCOMING
                sourceUuid = str(jsonData["sourceUuid"])
                sender = contactsDict[sourceUuid]
                recipient = groupName
            else:
                direction = CommunicationDirection.OUTGOING
                sender = accountOwnerInfo["profileName"]
                recipient = groupName
                        
        # If incoming message is seen by the suspect
        if str(seenStatus) == "2":
            readByString = accountOwnerInfo["profileName"]

        # If outgoing message is seen by other contacts
        if str(seenStatus) == "0":
            sendStateByConversationId = jsonData["sendStateByConversationId"]
            for conversationId, value in sendStateByConversationId.items():
                readBy = contactsDict[conversationId]
                if value["status"] == "Read":
                    if readByString:
                        readByString += ", "
                    readByString += readBy

        if isErased:
            body = "(Deleted)"

        if "quote" in jsonData:
            quotedMessage = jsonData["quote"]["text"]

        if "sticker" in jsonData:
            body = "(sticker)"

        additionalAttributes.add(BlackboardAttribute(readAtt,
                                                     moduleName, 
                                                     readByString))                                       
        additionalAttributes.add(BlackboardAttribute(quoteAtt,
                                                     moduleName, 
                                                     quotedMessage))
           
        # Post message artifact
        msgArt = helper.addMessage("Signal Message",
                                    direction,
                                    sender, 
                                    recipient, 
                                    timestamp,
                                    MessageReadStatus.UNKNOWN,
                                    "", #subject
                                    body,
                                    conversationId,
                                    additionalAttributes)

        # Link attachments to the message
        if hasAttachments:
            for attachment in jsonData["attachments"]:
                path = os.path.split(attachment["path"])
                attachmentFiles = fileManager.findFiles(dataSource, path[1], path[0])
                if attachmentFiles:
                    fileAttachments.add(FileAttachment(attachmentFiles[0]))
                else:
                    fileAttachments.add(FileAttachment(currentCase, dataSource, attachment["path"]))
            messageAttachment = MessageAttachments(fileAttachments,[])
            helper.addAttachments(msgArt, messageAttachment)

        # Link a sticker to the message
        if "sticker" in jsonData:
            path = os.path.split(jsonData["sticker"]["data"]["path"])
            stickerFiles = fileManager.findFiles(dataSource, path[1], path[0])
            if stickerFiles:
                stickers.add(FileAttachment(stickerFiles[0]))
            else:
                stickers.add(FileAttachment(currentCase, dataSource, jsonData["sticker"]["data"]["path"]))
            messageAttachment = MessageAttachments(stickers,[])
            helper.addAttachments(msgArt, messageAttachment)


def parseCalls(stmt, accountOwnerInfo, contactsDict, helper, moduleName):
    """Retrieves logs of calls made on Signal account and posts them in Autopsy's Blackboard.

    Args:
        stmt (object of 'org.sqlite.jdbc4.JDBC4Statement'): A database statement used to execute queries. 
        accountOwnerInfo (dict): A dictionary of account owner info, including phone number and profile name.
        contactsDict (dict): A dictionary that stores contacts information.
        helper (object of 'org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper'): Used to post calls to the blackboard.
        moduleName (str): Name of the ingest module 'SignalDesktopAnalyzer'
    """
        
    currentCase = Case.getCurrentCase().getSleuthkitCase()
    additionalAttributes = ArrayList()

    query = """SELECT messages.json,
                      profileFullName
                FROM messages
                INNER JOIN conversations ON messages.conversationId = conversations.id
                WHERE messages.type IS "call-history"
                ORDER BY rowid ASC
            """
        
    resultSet = stmt.executeQuery(query)

    # Create custome artifact attributes
    callResponseAtt = currentCase.addArtifactAttributeType("SIGNAL_CALL_RESPONSE",
                                                            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                            "Response")
    callModeAtt = currentCase.addArtifactAttributeType("SIGNAL_CALL_MODE",
                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                        "Mode")

    # Cycle through each row and create artifacts
    while resultSet.next():
                
            jsonString = resultSet.getString("json")
            jsonData = json.loads(jsonString)
            callMode = jsonData["callHistoryDetails"]["callMode"]

            # If group call:
            if callMode == "Group":
                # Get group name associated wiht the conversationId
                conversationId = jsonData["conversationId"]
                groupName = contactsDict[conversationId]
                callerUuid = str(jsonData["callHistoryDetails"]["creatorUuid"])
                # Get profile name associated with the creatorUuid
                profileName = contactsDict[callerUuid]
                callAcceptedTime = jsonData["callHistoryDetails"]["startedTime"] / 1000
                callEndedTime = 0
                direction = CommunicationDirection.UNKNOWN
                caller = profileName
                callee = groupName
                if profileName == accountOwnerInfo["profileName"]:
                    response = "Initiated"
                    direction = CommunicationDirection.OUTGOING
                else:
                    direction = CommunicationDirection.INCOMING
                    response = "Joined"

            # If direct call:
            else:
                profileName = resultSet.getString("profileFullName")
                callEndedTime = jsonData["callHistoryDetails"]["endedTime"] / 1000
                wasIncoming = jsonData["callHistoryDetails"]["wasIncoming"]
                # If call was accepted:
                if "acceptedTime" in jsonData["callHistoryDetails"]:
                    callAcceptedTime = jsonData["callHistoryDetails"]["acceptedTime"] / 1000
                    response = "Answered"
                else: 
                    callAcceptedTime = 0
                    response = "Declined"  
                if wasIncoming:
                    direction = CommunicationDirection.INCOMING
                    caller = profileName
                    callee = accountOwnerInfo["profileName"]
                else:
                    direction = CommunicationDirection.OUTGOING
                    caller = accountOwnerInfo["profileName"]
                    callee = profileName

            additionalAttributes.add(BlackboardAttribute(callResponseAtt,
                                                        moduleName, 
                                                        response))
            additionalAttributes.add(BlackboardAttribute(callModeAtt,
                                                        moduleName, 
                                                        callMode))

            # Post call log artifact
            helper.addCalllog(direction,
                            caller,
                            callee,
                            callAcceptedTime,
                            callEndedTime,
                            CallMediaType.UNKNOWN,
                            additionalAttributes)


def parseDeletedMsgs(pathToDecryptedWAL, walFile, contactsDict, accountOwnerInfo, moduleName):
    """Recover recently deleted messages from the WAL file of Signal's database and posts them in Autopsy's Blackboard.

    Args:
        pathToDecryptedWAL (str): Path of the WAL file that messages are recovered from.
        walFile (object of AbstractFile): Represents the WAL file in the datasource that recovered artifcts are liked to.
        accountOwnerInfo (dict): A dictionary of account owner info, including phone number and profile name.
        contactsDict (dict): A dictionary that stores contacts information.
        moduleName (str): Name of the ingest module 'SignalDesktopAnalyzer'
    """

    deletedMsgsIDs = []
    deletedMsgsBodies = []
    deletedMsgs = []
    ID_LENGTH = 36
    TYPE_LENGTH = 8

    with open(pathToDecryptedWAL, 'r') as fin:
        data = fin.readlines()
        # Find deleted messages' IDs
        for line in data:
            if '"isErased":true' in line:
                index = line.find('"id":"')
                # If an id is found
                if index != -1:
                    # Move index to the beginning of the id
                    index += len('"id":"')
                    # Do not read out of bound
                    if (index + ID_LENGTH) < len(line):
                        # Read id
                        msgID = line[index : index+ID_LENGTH]
                        if msgID not in deletedMsgsIDs:
                            deletedMsgsIDs.append(msgID)

        # Find deleted messages
        for line in data:
            for msgID in deletedMsgsIDs:
                if msgID in line:

                    # Find body
                    index = line.find('"body":"')
                    # If a body is found
                    if index != -1:
                        # Move index to the beginning of the body string
                        index += len('"body":"')
                        body = ''
                        # Read body until the substring '","' is found or the index reaches the end of the line
                        while (line[index : index+3] != '","'):
                            body += line[index]
                            index += 1
                            if (index + 3) >= len(line):
                                break
                        if (body != '') and (body not in deletedMsgsBodies):
                            deletedMsgsBodies.append(body)

                            # Find timestamp
                            index = line.find('"timestamp":')
                            # If timestamp is found
                            if index != -1:
                                # Move index to the beginning of the timestamp string
                                index += len('"timestamp":')
                                timestamp = ''
                                # Read timestamp until the character ',' is found or the index reaches the end of the line
                                while (line[index] != ','):
                                    timestamp += line[index]
                                    index += 1
                                    if index >= len(line):
                                        break

                            # Find type
                            index = line.find('"type":"')
                            # If a type is found
                            if index != -1:
                                # Move index to the beginning of the type string
                                index += len('"type":"')
                                # Do not read out of bound
                                if (index + TYPE_LENGTH) < len(line):
                                    # Read message type
                                    msgType = line[index : index+TYPE_LENGTH]

                            # Find conversation id
                            index = line.find('"conversationId":"')
                            # If a conversation id is found
                            if index != -1:
                                # Move index to the beginning of the conversation id string
                                index += len('"conversationId":"')
                                # Do not read out of bound
                                if (index + ID_LENGTH) < len(line):
                                    # Read conversation id
                                    convId = line[index : index+ID_LENGTH]

                            msg = {"body": body, "timestamp": int(int(timestamp) / 1000), "type": msgType, "convId": convId}
                            deletedMsgs.append(msg)

    if deletedMsgs:
        
        # Add custom artifact type for deleted Signal messages
        currentCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = currentCase.getBlackboard()
        deletedMsgArt = currentCase.addBlackboardArtifactType("DELETED_SIGNAL_MSG", "Deleted Signal Message")

        # Create custome artifact attributes
        directionAtt = currentCase.addArtifactAttributeType("DELETED_SIGNAL_MSG_DIRECTION",
                                                            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                            "Direction")
        senderAtt = currentCase.addArtifactAttributeType("DELETED_SIGNAL_MSG_SENDER",
                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                        "Sender")
        receiverAtt = currentCase.addArtifactAttributeType("DELETED_SIGNAL_MSG_RECEIVER",
                                                            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                                            "Receiver")

        for msg in deletedMsgs:

            # Create deleted Signal message artifact 
            art = walFile.newArtifact(deletedMsgArt.getTypeID())
                    
            additionalAttributes = ArrayList()
            additionalAttributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT, 
                                                        moduleName, 
                                                        msg["body"]))
            additionalAttributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, 
                                                        moduleName, 
                                                        msg["timestamp"]))
            additionalAttributes.add(BlackboardAttribute(directionAtt, 
                                                        moduleName, 
                                                        msg["type"]))

            if msg["type"] == "incoming":
                sender = contactsDict[msg["convId"]]
                receiver = accountOwnerInfo["profileName"]
            else:
                sender = accountOwnerInfo["profileName"]
                receiver = contactsDict[msg["convId"]]

            additionalAttributes.add(BlackboardAttribute(senderAtt, 
                                                        moduleName, 
                                                        sender))
            additionalAttributes.add(BlackboardAttribute(receiverAtt, 
                                                        moduleName, 
                                                        receiver))
            art.addAttributes(additionalAttributes)

            # Post deleted message artifact
            blackboard.postArtifact(art, 
                                    moduleName)

