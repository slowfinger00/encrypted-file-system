**Overview**

This project implements a secure, end-to-end encrypted file storage and sharing system in Go. Each user can store, append, load, and share files while ensuring confidentiality, integrity, and access control using cryptographic primitives provided by the CS161 userlib library.

The system is designed to:

- Prevent unauthorized data access or tampering, even from the untrusted server (Datastore)
- Support secure multi-user file sharing with revocable access
- Defend against rollback, reordering, and forgery attacks

**Features Implemented**

1) User Authentication
- Users are uniquely identified by usernames.
- Passwords are hashed with userlib.Hash() before use.
- User structs are symmetrically encrypted and signed for integrity.

2) File Operations
- StoreFile(filename, content): Creates or replaces a file.
- AppendToFile(filename, content): Adds data to the end of the file, using a chunked structure.
- LoadFile(filename): Retrieves and reconstructs the full file content.

3) Secure File Sharing
- CreateInvitation(filename, recipientUsername): Allows a user to share access to a file via a signed and encrypted invitation.
- AcceptInvitation(senderUsername, invitationPtr, filename): Lets the recipient gain access to the shared file under a local alias.
- RevokeAccess(filename, recipientUsername): Revokes access to a shared file, breaking the recipient’s access chain.

**Security Properties**
- Confidentiality: File contents and metadata are encrypted.
- Integrity: All data is authenticated with HMAC or digital signatures.
- Replay Protection: HMACs prevent rollback/replay attacks.
- Access Control: Only intended recipients can decrypt and access shared files.
- Revocation: Re-routes all access paths and changes UUIDs to prevent continued access after revocation.
