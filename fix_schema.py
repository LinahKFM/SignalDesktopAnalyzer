"""Removes some SQLite 3.3 syntax from Signal Desktop database.

- Recreates three tables of the SQLite database generated by Signal Desktop 
client, including messages, preKeys, and signedPreKeys tables.
- The purpose of recreation is to remove uses of the keyword "GENERATED 
ALWAYS AS" because the database is then used in a software that does not 
support the use of this keyword (Autopsy).

Args:
  Takes a path of SQLite database generated by Signal Desktop client.
"""

import sqlite3
import sys

# Get path of Signal Desktop database 
pathToDB = sys.argv[1]

# Column names of messages table
messagesColumns = """rowid, 
                    id,
                    json,
                    readStatus,
                    expires_at,
                    sent_at,
                    schemaVersion,
                    conversationId,
                    received_at,
                    source,
                    deprecatedSourceDevice,
                    hasAttachments,
                    hasFileAttachments,
                    hasVisualMediaAttachments,
                    expireTimer,
                    expirationStartTimestamp,
                    type,
                    body,
                    messageTimer,
                    messageTimerStart,
                    messageTimerExpiresAt,
                    isErased,
                    isViewOnce,
                    sourceUuid,
                    serverGuid,
                    expiresAt,
                    sourceDevice,
                    storyId,
                    isStory, 
                    isChangeCreatedByUs,
                    shouldAffectActivity,
                    shouldAffectPreview,
                    isUserInitiatedMessage,
                    isTimerChangeFromSync,
                    isGroupLeaveEvent,
                    isGroupLeaveEventFromOther,
                    seenStatus"""

# Column names and types of messages table
messagesColumnsWithTypes = """rowid INTEGER PRIMARY KEY ASC, 
                              id STRING UNIQUE,
                              json TEXT,
                              readStatus INTEGER,
                              expires_at INTEGER,
                              sent_at INTEGER,
                              schemaVersion INTEGER,
                              conversationId STRING,
                              received_at INTEGER,
                              source STRING,
                              deprecatedSourceDevice STRING,
                              hasAttachments INTEGER,
                              hasFileAttachments INTEGER,
                              hasVisualMediaAttachments INTEGER,
                              expireTimer INTEGER,
                              expirationStartTimestamp INTEGER,
                              type STRING,
                              body TEXT,
                              messageTimer INTEGER,
                              messageTimerStart INTEGER,
                              messageTimerExpiresAt INTEGER,
                              isErased INTEGER,
                              isViewOnce INTEGER,
                              sourceUuid TEXT, 
                              serverGuid STRING NULL, 
                              expiresAt INT, 
                              sourceDevice INTEGER, 
                              storyId STRING, 
                              isStory INTEGER, 
                              isChangeCreatedByUs INTEGER, 
                              shouldAffectActivity INTEGER,
                              shouldAffectPreview INTEGER, 
                              isUserInitiatedMessage INTEGER,
                              isTimerChangeFromSync INTEGER,
                              isGroupLeaveEvent INTEGER, 
                              isGroupLeaveEventFromOther INTEGER, 
                              seenStatus NUMBER"""

# Column names of preKeys and signedPreKeys tables
preKeysColumns = """id,
                    json"""

# Column names and types of preKeys and signedPreKeys tables
preKeysColumnsWithTypes = """id STRING,
                              json TEXT"""

try:
  
  # Connect to the database and create a cursor
  sqliteConnection = sqlite3.connect(pathToDB)
  cursor = sqliteConnection.cursor()

  # Fix messages table:

  # Get all rows in messages table
  cursor.execute("""SELECT %s 
                    FROM messages""" % messagesColumns)
  # Fetch result
  result = cursor.fetchall()

  # Delete messages table
  cursor.execute("DROP TABLE messages")

  # Create a new messages table
  query = """CREATE TABLE messages (%s)""" % messagesColumnsWithTypes
  cursor.execute(query)

  # Insert the previously fetched rows into the new messages table
  query = """INSERT INTO messages (%s)
              VALUES (?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, 
                      ?, ?)""" % messagesColumns

  for tuple in result:
    cursor.execute(query, tuple)
    sqliteConnection.commit()
  

  # Fix preKeys table:

  # Get all rows in preKeys table
  cursor.execute("""SELECT %s 
                    FROM preKeys""" % preKeysColumns)
  # Fetch result
  result = cursor.fetchall()

  # Delete preKeys table
  cursor.execute("DROP TABLE preKeys")

  # Create a new preKeys table
  query = """CREATE TABLE preKeys (%s)""" % preKeysColumnsWithTypes
  cursor.execute(query)

  # Insert the previously fetched rows into the new preKeys table
  query = """INSERT INTO preKeys (%s)
              VALUES (?, ?)""" % preKeysColumns

  for tuple in result:
    cursor.execute(query, tuple)
    sqliteConnection.commit()


  # Fix signedPreKeys table:

  # Get all rows in signedPryKeys table
  cursor.execute("""SELECT %s 
                    FROM signedPreKeys""" % preKeysColumns)
  # Fetch result
  result = cursor.fetchall()

  # Delete signedPreKeys table
  cursor.execute("DROP TABLE signedPreKeys")

  # Create a new signedPreKeys table
  query = """CREATE TABLE signedPreKeys (%s)""" % preKeysColumnsWithTypes
  cursor.execute(query)

  # Insert the previously fetched rows into the new signedPreKeys table
  query = """INSERT INTO signedPreKeys (%s)
              VALUES (?, ?)""" % preKeysColumns

  for tuple in result:
    cursor.execute(query, tuple)
    sqliteConnection.commit()
          
  # Close the cursor
  cursor.close()

# Handle errors
except sqlite3.Error as error:
  print('Error occured: ', error)
  
# Close database connection
finally:

  if sqliteConnection:
    sqliteConnection.close()
    print('SQLite Connection closed')