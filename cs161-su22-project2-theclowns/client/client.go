package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username  []byte
	Password  []byte
	Sksign    userlib.DSSignKey
	Skdecrypt userlib.PKEDecKey
	FileNames map[string]uuid.UUID
	FileKeys  map[string][]byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content []byte
	Next    uuid.UUID
	IsFile  bool
}

type FilePointer struct {
	FileAddress uuid.UUID
	SharedTo    map[string]uuid.UUID
	Key         []byte
	IsFile      bool
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	user_len := len(username)

	if user_len == 0 {
		fmt.Println("Invalid username. Username length must be greater than 0")
	} else {
		hash := userlib.Hash([]byte(username))
		usernameUUID, err := uuid.FromBytes(hash[len(hash)-16:])
		if err != nil {
			fmt.Println("An error occurred while generating a new UUID: ")
		}

		// Check if username has already been taken
		if _, ok := userlib.DatastoreGet(usernameUUID); ok {
			fmt.Println("This username already exists. Choose another username!")
		} else {
			userdata.Username = hash
			userdata.Password = userlib.Hash([]byte(password))
			userdata.FileNames = make(map[string]uuid.UUID)
			userdata.FileKeys = make(map[string][]byte)

			var pkencrypt userlib.PKEEncKey
			var skdecrypt userlib.PKEDecKey
			pkencrypt, skdecrypt, _ = userlib.PKEKeyGen()

			userdata.Skdecrypt = skdecrypt

			PKstoreset := append(userdata.Username[len(userdata.Username)-13:], []byte("PKE")...)

			pkencryptUUID, err := uuid.FromBytes(PKstoreset[:16])
			if err != nil {
				fmt.Println("An error occurred while generating a UUID")
			}

			userlib.KeystoreSet(pkencryptUUID.String(), pkencrypt)

			DSsignkey, DSverifykey, _ := userlib.DSKeyGen()

			userdata.Sksign = DSsignkey

			DSstoreset := append(userdata.Username[len(userdata.Username)-14:], []byte("DS")...) //Pre-UUID for DSVerify

			DSverifyUUID, err := uuid.FromBytes(DSstoreset[:16])
			if err != nil {
				fmt.Println("An error occurred while generating a UUID")
			}

			userlib.KeystoreSet(DSverifyUUID.String(), DSverifykey)

			DataStoreEncrypt, err := userlib.HashKDF(usernameUUID[:16], []byte("User")) //Encryption key for User struct
			if err != nil {
				fmt.Println("An error occurred while generating derived key")
			}

			IV := userlib.RandomBytes(16)

			userdatabytes, err := json.Marshal(userdata)
			if err != nil {
				fmt.Println("An error occurred while converting struct to JSON.")
			}

			UserEncrypted := userlib.SymEnc(DataStoreEncrypt[:16], IV, userdatabytes)

			Signature, err := userlib.DSSign(DSsignkey, UserEncrypted)
			if err != nil {
				fmt.Println("Something went wrong in signing.")
			}
			UserEncDS := append(UserEncrypted, Signature...)

			userlib.DatastoreSet(usernameUUID, UserEncDS)
		}
	}

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	hash := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hash[len(hash)-16:])
	if err != nil {
		fmt.Println("An error occurred while generating a new UUID: ")
	}

	// Check if username exist
	if _, ok := userlib.DatastoreGet(usernameUUID); !ok {
		fmt.Println("This username does not exist.")
	} else {
		DSstoresetup := append(hash[len(hash)-14:], []byte("DS")...)

		//Process to obtain DS Verification key from keystore
		DSverifyUUID, err := uuid.FromBytes(DSstoresetup[:16])
		if err != nil {
			fmt.Println("An error occurred while generating a UUID")
		}

		DSVerifykey, ok := userlib.KeystoreGet(DSverifyUUID.String())
		if !ok {
			fmt.Println("Error in retrieving DS verification key")
		}

		//Get user data from datastore
		UsernameUUID, err := uuid.FromBytes(hash[len(hash)-16:])
		if err != nil {
			fmt.Println("An error occurred while generating a new UUID: ")
		}
		UserEncDS, ok := userlib.DatastoreGet(UsernameUUID)
		if !ok {
			fmt.Println("No data at given UUID")
		}

		//Verify integrity of User data
		if err := userlib.DSVerify(DSVerifykey, UserEncDS[:(len(UserEncDS)-256)], UserEncDS[(len(UserEncDS)-256):]); err != nil {
			fmt.Println("Verification of DS failed.")
		} else {
			DataStoreEncrypt, err := userlib.HashKDF(usernameUUID[:16], []byte("User"))
			if err != nil {
				fmt.Println("An error occurred while generating derived key")
			}
			//Obtain User data decrypted
			UserDecrypted := userlib.SymDec(DataStoreEncrypt[:16], UserEncDS[:len(UserEncDS)-256])
			err = json.Unmarshal(UserDecrypted, userdataptr)
			if err != nil {
				return nil, err
			}
		}
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//Get latest User struct information
	UserUUID, err := uuid.FromBytes(userdata.Username[len(userdata.Username)-16:])
	if err != nil {
		return errors.New("An error occurred while generating User UUID.")
	}
	UserEncDS, ok := userlib.DatastoreGet(UserUUID)
	if !ok {
		fmt.Println("No data at given UUID")
	}
	//Process to obtain DS Verification key from keystore
	DSstoresetup := append(userdata.Username[len(userdata.Username)-14:], []byte("DS")...)
	DSverifyUUID, err := uuid.FromBytes(DSstoresetup[:16])
	if err != nil {
		fmt.Println("An error occurred while generating a UUID")
	}

	DSVerifykey, ok := userlib.KeystoreGet(DSverifyUUID.String())
	if !ok {
		fmt.Println("Error in retrieving DS verification key")
	}
	//Verify integrity of User data
	if err := userlib.DSVerify(DSVerifykey, UserEncDS[:(len(UserEncDS)-256)], UserEncDS[(len(UserEncDS)-256):]); err != nil {
		fmt.Println("Verification of DS failed.")
	} else {
		DataStoreEncrypt, err := userlib.HashKDF(UserUUID[:16], []byte("User"))
		if err != nil {
			fmt.Println("An error occurred while generating derived key")
		}
		//Obtain User data decrypted
		UserDecrypted := userlib.SymDec(DataStoreEncrypt[:16], UserEncDS[:len(UserEncDS)-256])
		err = json.Unmarshal(UserDecrypted, userdata)
		if err != nil {
			return errors.New("An error occurred while unmarshalling Updated User struct.")
		}
	}

	//Check if filename exists in Caller's namespace
	if _, ok := userdata.FileNames[filename]; ok {
		FileptrUUID := userdata.FileNames[filename]
		FileKey := userdata.FileKeys["filename"]
		FileptrEncMAC, ok := userlib.DatastoreGet(FileptrUUID)
		if !ok {
			return errors.New("An error occurred while retrieving File Pointer.")
		}
		HMAC := FileptrEncMAC[len(FileptrEncMAC)-64:]
		FileptrEnc := FileptrEncMAC[:len(FileptrEncMAC)-64]
		HMACverify, err := userlib.HMACEval(FileKey, FileptrEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for verification.")
		}
		equal := userlib.HMACEqual(HMAC, HMACverify)
		if equal != true {
			return errors.New("Verification test failed for File Pointer.")
		}
		FileptrDec := userlib.SymDec(FileKey, FileptrEnc)

		//Initialise Local FilePointer for storage
		var filepointer FilePointer
		err = json.Unmarshal(FileptrDec, &filepointer)
		if err != nil {
			return errors.New("An error occurred while unmarshalling File Pointer.")
		}

		//Retrieve Data from the address written in File Pointer
		FPaddress := filepointer.FileAddress
		FileptrEncMAC, ok = userlib.DatastoreGet(FPaddress)
		if !ok {
			return errors.New("An error occurred while retrieving FilePointer/File from datastore.")
		}
		HMAC = FileptrEncMAC[len(FileptrEncMAC)-64:]
		FileptrEnc = FileptrEncMAC[:len(FileptrEncMAC)-64]
		HMACverify, err = userlib.HMACEval(FileKey, FileptrEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for verification.")
		}
		equal = userlib.HMACEqual(HMAC, HMACverify)
		if equal != true {
			return errors.New("Verification test failed for File Pointer.")
		}
		FileptrDec = userlib.SymDec(FileKey, FileptrEnc)
		//Overwrite local filepointer with new file pointer
		err = json.Unmarshal(FileptrDec, &filepointer)
		if err != nil {
			return errors.New("An error occurred while unmarshalling file pointer data.")
		}
		//Initialise local File struct for storage
		var file File
		file.Next = uuid.Nil
		file.Content = content
		Filebytes, err := json.Marshal(file)
		if err != nil {
			return errors.New("An error occurred while maarshalling File content.")
		}
		IV := userlib.RandomBytes(16)
		FileEnc := userlib.SymEnc(FileKey, IV, Filebytes)
		HMAC, err = userlib.HMACEval(FileKey, FileEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for File.")
		}
		FileEncMAC := append(FileEnc, HMAC...)
		userlib.DatastoreSet(FPaddress, FileEncMAC)
	} else {
		//Create instance of File, and store file with contents in the datastore
		var file File
		FileStorage := uuid.New()
		FileKey := userlib.RandomBytes(16)
		file.Content = content
		file.Next = uuid.Nil
		file.IsFile = true
		fileBytes, err := json.Marshal(file)
		if err != nil {
			fmt.Println("Error occurred in marshalling file")
		}
		IV := userlib.RandomBytes(16)
		FileEnc := userlib.SymEnc(FileKey, IV, fileBytes)
		HMAC, err := userlib.HMACEval(FileKey, FileEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for File.")
		}
		FileEncMAC := append(FileEnc, HMAC...)
		userlib.DatastoreSet(FileStorage, FileEncMAC)
		//Create instance of FilePointer, and store FilePointer in the datastore
		var Fileptr FilePointer
		FilePtrUUID := uuid.New()
		Fileptr.FileAddress = FileStorage
		Fileptr.Key = make([]byte, 0)
		Fileptr.SharedTo = make(map[string]uuid.UUID)
		Fileptr.IsFile = false
		userdata.FileNames[filename] = FilePtrUUID
		FileptrBytes, err := json.Marshal(Fileptr)
		if err != nil {
			return errors.New("An error occurred while marshalling File Pointer.")
		}
		IV = userlib.RandomBytes(16)
		FileptrEnc := userlib.SymEnc(FileKey, IV, FileptrBytes)
		HMAC, err = userlib.HMACEval(FileKey, FileptrEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for File Pointer.")
		}
		FilePtrEncMAC := append(FileptrEnc, HMAC...)
		userlib.DatastoreSet(FilePtrUUID, FilePtrEncMAC)
		//Update User struct with the file names and keys
		userdata.FileNames[filename] = FilePtrUUID
		userdata.FileKeys[filename] = FileKey
		DSsignKey := userdata.Sksign
		UserUUID, err := uuid.FromBytes(userdata.Username[len(userdata.Username)-16:])
		if err != nil {
			return errors.New("An error occurred while generating User struct UUID")
		}
		UserEncKey, err := userlib.HashKDF(UserUUID[:16], []byte("User")) //Encryption key for User struct
		if err != nil {
			fmt.Println("An error occurred while generating derived key")
		}
		UserBytes, err := json.Marshal(userdata)
		if err != nil {
			return errors.New("An error occurred while marshalling User struct.")
		}
		IV = userlib.RandomBytes(16)
		UserBytesEnc := userlib.SymEnc(UserEncKey[:16], IV, UserBytes)
		Signature, err := userlib.DSSign(DSsignKey, UserBytesEnc)
		if err != nil {
			return errors.New("An error occurred while signing Digital Signature.")
		}
		UserEncSigned := append(UserBytesEnc, Signature...)
		userlib.DatastoreSet(UserUUID, UserEncSigned)
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	//Check if filename exists in namespace of caller
	if _, ok := userdata.FileNames[filename]; !ok {
		return errors.New("The Filename does not exist in the given namespace.")
	}
	//Retrieve File Pointer from Datastore, and check integrity
	FileptrUUID := userdata.FileNames[filename]
	FileKey := userdata.FileKeys[filename]
	FileptrEncMAC, ok := userlib.DatastoreGet(FileptrUUID)
	if !ok {
		return errors.New("An error occurred while retrieving FilePointer from datastore.")
	}
	HMAC := FileptrEncMAC[len(FileptrEncMAC)-64:]
	FileptrEnc := FileptrEncMAC[:len(FileptrEncMAC)-64]
	HMACverify, err := userlib.HMACEval(FileKey, FileptrEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for verification.")
	}
	equal := userlib.HMACEqual(HMAC, HMACverify)
	if equal != true {
		return errors.New("Verification test failed for File Pointer.")
	}
	FileptrDec := userlib.SymDec(FileKey, FileptrEnc)
	//Initialise local filepointer and get data
	var filepointer FilePointer
	err = json.Unmarshal(FileptrDec, &filepointer)
	if err != nil {
		return errors.New("An error occurred while unmarshalling File Pointer Data.")
	}
	//Initialise Local File Struct for repeated collection of File chunks data
	var file File

	//Traverse through the file pointer structs until reaches first file struct

	FileUUID := file.Next //For whole function usage

	for filepointer.IsFile != true {
		FileptrUUID = filepointer.FileAddress
		FileUUID = FileptrUUID
		FileptrEncMAC, ok = userlib.DatastoreGet(FileptrUUID)
		if !ok {
			return errors.New("An error occurred while retrieving FilePointer from datastore.")
		}
		HMAC = FileptrEncMAC[len(FileptrEncMAC)-64:]
		FileptrEnc = FileptrEncMAC[:len(FileptrEncMAC)-64]
		HMACverify, err = userlib.HMACEval(FileKey, FileptrEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for verification.")
		}
		equal = userlib.HMACEqual(HMAC, HMACverify)
		if equal != true {
			return errors.New("Verification test failed for File Pointer.")
		}
		FileptrDec = userlib.SymDec(FileKey, FileptrEnc)
		err = json.Unmarshal(FileptrDec, &filepointer)

		if filepointer.IsFile == true {
			er := json.Unmarshal(FileptrDec, &file)
			if er != nil {
				return errors.New("An error occurred while unmarshalling File data in er.")
			}
		}
	}

	//Traverse through the File structs until reached the Last file
	for file.Next != uuid.Nil {
		fmt.Println("jpdsfvns")
		FileUUID = file.Next
		FileEncMAC, ok := userlib.DatastoreGet(FileUUID)
		if !ok {
			return errors.New("An error occurred while retrieving FilePointer from datastore.")
		}
		HMAC := FileEncMAC[len(FileEncMAC)-64:]
		FileEnc := FileEncMAC[:len(FileEncMAC)-64]
		HMACverify, err := userlib.HMACEval(FileKey, FileEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for verification.")
		}
		equal := userlib.HMACEqual(HMAC, HMACverify)
		if equal != true {
			return errors.New("Verification test failed for File Pointer.")
		}
		FileDec := userlib.SymDec(FileKey, FileEnc)
		err = json.Unmarshal(FileDec, &file)
		if err != nil {
			return errors.New("An error occurred while unmarshalling data to File Pointer.")
		}
	}
	//Deal with Final File Chunk (contains Next = Nil)

	NextFileUUID := uuid.New()
	file.Next = NextFileUUID
	FileBytes, err := json.Marshal(file)
	if err != nil {
		return errors.New("An error occurred while marshalling last file chunk.")
	}
	IV := userlib.RandomBytes(16)
	FileEnc := userlib.SymEnc(FileKey, IV, FileBytes)
	HMAC, err = userlib.HMACEval(FileKey, FileEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for Last File Chunk.")
	}
	FileEncMAC := append(FileEnc, HMAC...)
	userlib.DatastoreSet(FileUUID, FileEncMAC)

	//Append New file chunk
	file.Next = uuid.Nil
	file.Content = content

	FileBytes, err = json.Marshal(file)
	if err != nil {
		return errors.New("An error occurred while marshalling Appended File data.")
	}
	IV = userlib.RandomBytes(16)
	FileEnc = userlib.SymEnc(FileKey, IV, FileBytes)
	HMAC, err = userlib.HMACEval(FileKey, FileEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for New file chunk.")
	}
	FileEncMAC = append(FileEnc, HMAC...)
	userlib.DatastoreSet(NextFileUUID, FileEncMAC)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//Check if filename exists in Caller's Namespace
	if _, ok := userdata.FileNames[filename]; !ok {
		return nil, errors.New("Filename does not exist in Caller's namespace.")
	}

	//Get File Pointer from Datastore
	FileptrUUID := userdata.FileNames[filename]
	FileptrEncMAC, ok := userlib.DatastoreGet(FileptrUUID)
	if !ok {
		return nil, errors.New("An error occurred while retrieving File pointer data from datastore.")
	}

	//Verify Integrity of File Pointer
	var filepointer FilePointer
	FileKey := userdata.FileKeys[filename]
	HMAC := FileptrEncMAC[len(FileptrEncMAC)-64:]
	FileptrEnc := FileptrEncMAC[:len(FileptrEncMAC)-64]
	HMACverify, err := userlib.HMACEval(FileKey, FileptrEnc)
	equal := userlib.HMACEqual(HMAC, HMACverify)
	if equal != true {
		return nil, errors.New("Verification Test failed for File Pointer integrity.")
	}
	FileptrDec := userlib.SymDec(FileKey, FileptrEnc)

	//Initialise Local File Struct for repeated collection of File chunks data
	var file File

	//Traverse through the file pointer structs until reach first file struct
	err = json.Unmarshal(FileptrDec, &filepointer)
	for filepointer.IsFile != true {
		FileptrUUID = filepointer.FileAddress
		FileptrEncMAC, ok = userlib.DatastoreGet(FileptrUUID)
		if !ok {
			return nil, errors.New("An error occurred while retrieving FilePointer from datastore.")
		}
		HMAC = FileptrEncMAC[len(FileptrEncMAC)-64:]
		FileptrEnc = FileptrEncMAC[:len(FileptrEncMAC)-64]
		HMACverify, err = userlib.HMACEval(FileKey, FileptrEnc)
		if err != nil {
			return nil, errors.New("An error occurred while generating HMAC for verification.")
		}
		equal = userlib.HMACEqual(HMAC, HMACverify)
		if equal != true {
			return nil, errors.New("Verification test failed for File Pointer.")
		}
		FileptrDec = userlib.SymDec(FileKey, FileptrEnc)
		err = json.Unmarshal(FileptrDec, &filepointer)
		if filepointer.IsFile == true {
			er := json.Unmarshal(FileptrDec, &file)
			if er != nil {
				return nil, errors.New("An error occurred while unmarshalling File data in er.")
			}
		}
	}
	FileUUID := file.Next //For whole function usage

	//Traverse through the File structs and download the data
	for file.Next != uuid.Nil {
		FileUUID = file.Next
		DownloadedContent := file.Content
		content = append(content, DownloadedContent...)
		FileEncMAC, ok := userlib.DatastoreGet(FileUUID)
		if !ok {
			return nil, errors.New("An error occurred while retrieving FilePointer from datastore.")
		}
		HMAC := FileEncMAC[len(FileEncMAC)-64:]
		FileEnc := FileEncMAC[:len(FileEncMAC)-64]
		HMACverify, err := userlib.HMACEval(FileKey, FileEnc)
		if err != nil {
			return nil, errors.New("An error occurred while generating HMAC for verification.")
		}
		equal := userlib.HMACEqual(HMAC, HMACverify)
		if equal != true {
			return nil, errors.New("Verification test failed for File Pointer.")
		}
		FileDec := userlib.SymDec(FileKey, FileEnc)
		err = json.Unmarshal(FileDec, &file)
		if err != nil {
			return nil, errors.New("An error occurred while unmarshalling data to File Pointer.")
		}
	}
	DownloadedContent := file.Content
	content = append(content, DownloadedContent...)

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//Get latest User struct information
	UserUUID, err := uuid.FromBytes(userdata.Username[len(userdata.Username)-16:])
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while generating User UUID.")
	}
	UserEncDS, ok := userlib.DatastoreGet(UserUUID)
	if !ok {
		fmt.Println("No data at given UUID")
	}
	//Process to obtain DS Verification key from keystore
	DSstoresetup := append(userdata.Username[len(userdata.Username)-14:], []byte("DS")...)
	DSverifyUUID, err := uuid.FromBytes(DSstoresetup[:16])
	if err != nil {
		fmt.Println("An error occurred while generating a UUID")
	}

	DSVerifykey, ok := userlib.KeystoreGet(DSverifyUUID.String())
	if !ok {
		fmt.Println("Error in retrieving DS verification key")
	}
	//Verify integrity of User data
	if err := userlib.DSVerify(DSVerifykey, UserEncDS[:(len(UserEncDS)-256)], UserEncDS[(len(UserEncDS)-256):]); err != nil {
		fmt.Println("Verification of DS failed.")
	} else {
		DataStoreEncrypt, err := userlib.HashKDF(UserUUID[:16], []byte("User"))
		if err != nil {
			fmt.Println("An error occurred while generating derived key")
		}
		//Obtain User data decrypted
		UserDecrypted := userlib.SymDec(DataStoreEncrypt[:16], UserEncDS[:len(UserEncDS)-256])
		err = json.Unmarshal(UserDecrypted, userdata)
		if err != nil {
			return uuid.Nil, errors.New("An error occurred while unmarshalling Updated User struct.")
		}
	}

	//Error testing
	//Test that filename exists in caller's namespace

	if _, ok := userdata.FileNames[filename]; !ok {
		return uuid.Nil, errors.New("Filename does not exist in your namespace")
	}

	//Test that Recipient's username exists
	HashedRecipient := userlib.Hash([]byte(recipientUsername))
	RecipientUUID, err := uuid.FromBytes(HashedRecipient[len(HashedRecipient)-16:])
	if _, ok := userlib.DatastoreGet(RecipientUUID); !ok {
		return uuid.Nil, errors.New("Recipient Username does not exist")
	}

	//Prepare filepointer struct for recipient
	Addressptr := userdata.FileNames[filename]
	var fileptr FilePointer
	fileptr.FileAddress = Addressptr
	fileptr.SharedTo = make(map[string]uuid.UUID)
	fileptr.IsFile = false
	//Get File Symmetric key to send to recipient
	FileKey := userdata.FileKeys[filename]
	fileptr.Key = FileKey
	//Set up Datastoreset and upload filepointer struct to datastore
	//Recipient Public Key encryption retrieval
	invitationPtr = uuid.New()

	PKEncstorage := append(HashedRecipient[len(HashedRecipient)-13:], []byte("PKE")...)
	PKEnUUID, err := uuid.FromBytes(PKEncstorage)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while generating recipient PK UUID")
	}
	PKEncKey, ok := userlib.KeystoreGet(PKEnUUID.String())
	if !ok {
		return uuid.Nil, errors.New("An error occurred while retrieving recipient Public Key.")
	}
	InviteBytes, err := json.Marshal(fileptr)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while marshalling the invitation")
	}
	InviteEncrypted, err := userlib.PKEEnc(PKEncKey, InviteBytes)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while encrypting invitation")
	}
	//Sign invitation with sender's digital signature
	DSsignkey := userdata.Sksign
	Signature, err := userlib.DSSign(DSsignkey, InviteEncrypted)
	if err != nil {
		return uuid.Nil, errors.New("An error occcurred while signing")
	}
	InviteEncDS := append(InviteEncrypted, Signature...)
	userlib.DatastoreSet(invitationPtr, InviteEncDS)
	//Store the username of the recipient in the sender's Filepointer SharedTo map
	var fileptrsender FilePointer
	SenderptrEncMAC, ok := userlib.DatastoreGet(Addressptr)
	if !ok {
		return uuid.Nil, errors.New("An error occurred in retrieving sender's FilePointer")
	}
	//Ensure integrity of FilePtr
	SenderptrEnc := SenderptrEncMAC[:len(SenderptrEncMAC)-64]
	HMACattached := SenderptrEncMAC[len(SenderptrEncMAC)-64:]
	HMACmade, err := userlib.HMACEval(FileKey, SenderptrEnc)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred whie generating HMAC.")
	}
	equal := userlib.HMACEqual(HMACmade, HMACattached)
	if equal != true {
		return uuid.Nil, errors.New("The HMACs do not match.")
	}
	SenderptrDec := userlib.SymDec(FileKey, SenderptrEnc)
	err = json.Unmarshal(SenderptrDec, &fileptrsender)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while unmarshalling Sender pointer data.")
	}
	fileptrsender.SharedTo[recipientUsername] = invitationPtr
	//Send the Updated Sender file pointer back to the datastore
	IV := userlib.RandomBytes(16)
	FPSbytes, err := json.Marshal(fileptrsender)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while marshalling Sender pointer data.")
	}
	SenderReEnc := userlib.SymEnc(FileKey, IV, FPSbytes)
	HMAC2, err := userlib.HMACEval(FileKey, SenderReEnc)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while creating HMAC for updated sender pointer.")
	}
	SenderReEncMAC := append(SenderReEnc, HMAC2...)
	userlib.DatastoreSet(Addressptr, SenderReEncMAC)

	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//Get latest User struct information
	UserUUID, err := uuid.FromBytes(userdata.Username[len(userdata.Username)-16:])
	if err != nil {
		return errors.New("An error occurred while generating User UUID.")
	}
	UserEncDS, ok := userlib.DatastoreGet(UserUUID)
	if !ok {
		fmt.Println("No data at given UUID")
	}
	//Process to obtain DS Verification key from keystore
	DSstoresetup := append(userdata.Username[len(userdata.Username)-14:], []byte("DS")...)
	DSverifyUUID, err := uuid.FromBytes(DSstoresetup[:16])
	if err != nil {
		fmt.Println("An error occurred while generating a UUID")
	}

	DSVerifykey, ok := userlib.KeystoreGet(DSverifyUUID.String())
	if !ok {
		fmt.Println("Error in retrieving DS verification key")
	}
	//Verify integrity of User data
	if err := userlib.DSVerify(DSVerifykey, UserEncDS[:(len(UserEncDS)-256)], UserEncDS[(len(UserEncDS)-256):]); err != nil {
		fmt.Println("Verification of DS failed.")
	} else {
		DataStoreEncrypt, err := userlib.HashKDF(UserUUID[:16], []byte("User"))
		if err != nil {
			fmt.Println("An error occurred while generating derived key")
		}
		//Obtain User data decrypted
		UserDecrypted := userlib.SymDec(DataStoreEncrypt[:16], UserEncDS[:len(UserEncDS)-256])
		err = json.Unmarshal(UserDecrypted, userdata)
		if err != nil {
			return errors.New("An error occurred while unmarshalling Updated User struct.")
		}
	}

	//Check that caller does not have filename in his personal namespace
	if _, ok := userdata.FileNames[filename]; ok {
		return errors.New("Filename already exist.")
	}
	//Check that file share invitation is created by senderUsername
	InviteEncDS, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("An error occurred while retrieving invitation")
	}
	Signature := InviteEncDS[len(InviteEncDS)-256:]
	InviteEnc := InviteEncDS[:len(InviteEncDS)-256]
	HashedSender := userlib.Hash([]byte(senderUsername))
	DSstoreset := append(HashedSender[len(HashedSender)-14:], []byte("DS")...)
	DSVerifyUUID, err := uuid.FromBytes(DSstoreset[:16])
	if err != nil {
		return errors.New("An error occurred while generating the UUID to obtain Verification key.")
	}
	Verifykey, ok := userlib.KeystoreGet(DSVerifyUUID.String())
	if !ok {
		return errors.New("An error occurred while retrieving Verification key from keystore.")
	}
	err = userlib.DSVerify(Verifykey, InviteEnc, Signature)
	if err != nil {
		return errors.New("Digital Signature verification failed")
	}
	//Check that invitation is not revoked by sender
	InviteDec, err := userlib.PKEDec(userdata.Skdecrypt, InviteEnc)
	if err != nil {
		return errors.New("An error occurred while decrypting the message.")
	}
	var filepointer FilePointer
	filepointerptr := &filepointer

	err = json.Unmarshal(InviteDec, filepointerptr)
	if err != nil {
		return errors.New("An error occurred while unmarshalling the data.")
	}

	if filepointer.FileAddress == uuid.Nil {
		return errors.New("Your invitation has been revoked")
	}
	//Set filename: Fileptr UUID pair for user, and unmarshall data to FilePointer
	userdata.FileNames[filename] = invitationPtr
	userdata.FileKeys[filename] = filepointer.Key
	filepointer.Key = []byte{}

	//Send the updated Acceptee user data to the datastore
	DSsignkey := userdata.Sksign

	Userbytes, err := json.Marshal(userdata)
	if err != nil {
		return errors.New("An error occurred while marshalling Acceptee user data.")
	}

	DataStoreEncrypt, err := userlib.HashKDF(UserUUID[:16], []byte("User"))
	if err != nil {
		fmt.Println("An error occurred while generating derived key")
	}
	IV := userlib.RandomBytes(16)
	UserEnc := userlib.SymEnc(DataStoreEncrypt[:16], IV, Userbytes)

	Sign, err := userlib.DSSign(DSsignkey, UserEnc)
	UserEncDS = append(UserEnc, Sign...)
	AccepteeUUID, err := uuid.FromBytes(userdata.Username[len(userdata.Username)-16:])
	if err != nil {
		return errors.New("An error occurred while generating Acceptee's User UUID.")
	}
	userlib.DatastoreSet(AccepteeUUID, UserEncDS)

	//Send the Updated Acceptee file pointer back to the datastore
	IV = userlib.RandomBytes(16)
	FAPbytes, err := json.Marshal(filepointer)
	if err != nil {
		return errors.New("An error occurred while marshalling Acceptee file pointer data.")
	}
	AccepteeReEnc := userlib.SymEnc(userdata.FileKeys[filename], IV, FAPbytes)
	HMAC, err := userlib.HMACEval(userdata.FileKeys[filename], AccepteeReEnc)
	if err != nil {
		return errors.New("An error occurred while creating HMAC for updated Acceptee file pointer.")
	}
	AccepteeReEncMAC := append(AccepteeReEnc, HMAC...)
	userlib.DatastoreSet(invitationPtr, AccepteeReEncMAC)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//Test that filename exist in Caller's namespace
	if _, ok := userdata.FileNames[filename]; !ok {
		return errors.New("Filename does not exist in namespace.")
	}

	//Get Caller's file pointer struct
	UserFileptrUUID := userdata.FileNames[filename]
	UserFileptr, ok := userlib.DatastoreGet(UserFileptrUUID)
	if !ok {
		return errors.New("An error occurred while retrieving User File pointer.")
	}

	var CurrentFP FilePointer

	//Get File Key
	FileKey := userdata.FileKeys[filename]

	//Verify integrity of Caller's file pointer struct
	RMAC := UserFileptr[len(UserFileptr)-64:]
	UserFPEnc := UserFileptr[:len(UserFileptr)-64]
	HMAC, err := userlib.HMACEval(FileKey, UserFPEnc)
	if err != nil {
		return errors.New("An error occured whle generating HMAC.")
	}
	equal := userlib.HMACEqual(HMAC, RMAC)
	if equal != true {
		return errors.New("Caller's file pointer Verification test failed.")
	}
	//Store downloaded data in local FilePointer struct, and get recipient file pointer address
	UserFPDec := userlib.SymDec(FileKey, UserFPEnc)
	err = json.Unmarshal(UserFPDec, &CurrentFP)
	if err != nil {
		return errors.New("An error occurred while unmarshalling Caller's file pointer.")
	}
	if _, ok := CurrentFP.SharedTo[recipientUsername]; !ok {
		return errors.New("File is not shared to this recipient.")
	}
	RecipientptrAdd := CurrentFP.SharedTo[recipientUsername]

	//Get recipient file pointer data
	var RecipientFP FilePointer
	RecipientFPEncMAC, ok := userlib.DatastoreGet(RecipientptrAdd)

	//Verify integrity of recipient file pointer struct
	RMAC = RecipientFPEncMAC[len(RecipientFPEncMAC)-64:]
	RecipientFPEnc := RecipientFPEncMAC[:len(RecipientFPEncMAC)-64]
	HMAC, err = userlib.HMACEval(FileKey, RecipientFPEnc)
	if err != nil {
		return errors.New("An error occured whle generating HMAC for recipient.")
	}
	equal = userlib.HMACEqual(HMAC, RMAC)
	if equal != true {
		return errors.New("Recipient's file pointer Verification test failed.")
	}
	//Decrypt and store recipient's file pointer data locally
	RecipientFPDec := userlib.SymDec(FileKey, RecipientFPEnc)
	err = json.Unmarshal(RecipientFPDec, &RecipientFP)
	if err != nil {
		return errors.New("An error occurred while unmarshalling recipient's file pointer data.")
	}
	RecipientFP.FileAddress = uuid.Nil
	//Store Updated Revoked recipient data to datastore
	RecipientFPbytes, err := json.Marshal(RecipientFP)
	if err != nil {
		return errors.New("An error occurred while marshalling updated recipient file pointer.")
	}
	IV := userlib.RandomBytes(16)
	RecipientFPEncUP := userlib.SymEnc(FileKey, IV, RecipientFPbytes)
	NewHMAC, err := userlib.HMACEval(FileKey, RecipientFPEncUP)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for updated recipient file pointer.")
	}
	RecipientFPEncMACUP := append(RecipientFPEncUP, NewHMAC...)
	userlib.DatastoreSet(RecipientptrAdd, RecipientFPEncMACUP)

	//Delete recipient username from Caller's file pointer SharedTo map
	delete(CurrentFP.SharedTo, recipientUsername)

	//Randomise the address of Caller's' filepointer
	NewCallerFPUUID := uuid.New()

	//Update the new Caller's file pointer address to directly shared to users
	for AllowedUser := range CurrentFP.SharedTo {
		AllowedUserFPadd := CurrentFP.SharedTo[AllowedUser]
		AllowedUserFP, ok := userlib.DatastoreGet(AllowedUserFPadd)
		if !ok {
			return errors.New("An error occurred while retrieving Allowed User's file pointer data.")
		}
		//Verify integrity of the Allowed User File pointer, then decrypt and unmarshal allowed user file pointer
		HMAC := AllowedUserFP[len(AllowedUserFP)-64:]
		AllowedUserFPEnc := AllowedUserFP[:len(AllowedUserFP)-64]
		MACcheck, err := userlib.HMACEval(FileKey, AllowedUserFPEnc)
		if err != nil {
			return errors.New("An error occurred while creating verification HMAC for allowed user file pointer.")
		}
		equal := userlib.HMACEqual(HMAC, MACcheck)
		if equal != true {
			return errors.New("Verification test failed for Allowed User file pointer.")
		}
		AllowedUserFPDec := userlib.SymDec(FileKey, AllowedUserFPEnc)
		var AllowedFP FilePointer
		err = json.Unmarshal(AllowedUserFPDec, &AllowedFP)
		AllowedFP.FileAddress = NewCallerFPUUID
		AllowedFPbytes, err := json.Marshal(AllowedFP)
		if err != nil {
			return errors.New("An error occurred while marshalling the updated allowed user file pointer.")
		}
		IV := userlib.RandomBytes(16)
		AllowedFPEnc := userlib.SymEnc(FileKey, IV, AllowedFPbytes)
		NewMac, err := userlib.HMACEval(FileKey, AllowedFPEnc)
		if err != nil {
			return errors.New("An error occurred while making new HMAC for updated allowed user file pointer.")
		}
		AllowedFPEncMAC := append(AllowedFPEnc, NewMac...)
		userlib.DatastoreSet(AllowedUserFPadd, AllowedFPEncMAC)
	}
	//Randomise the addresses of File chunks
	//Get the FileChunk data from datastore, with integrity check
	var FileChunk File
	FileChunkUUID := CurrentFP.FileAddress
	FileChunkEncMAC, ok := userlib.DatastoreGet(FileChunkUUID)
	if !ok {
		return errors.New("An error has occurred while retrieving file chunk data.")
	}
	HMAC = FileChunkEncMAC[len(FileChunkEncMAC)-64:]
	FileChunkEnc := FileChunkEncMAC[:len(FileChunkEncMAC)-64]
	MACverify, err := userlib.HMACEval(FileKey, FileChunkEnc)
	if err != nil {
		return errors.New("An error occurred while generating verification HMAC")
	}
	equal = userlib.HMACEqual(HMAC, MACverify)
	if equal != true {
		return errors.New("Verification test failed for file chunk.")
	}
	FileChunkDec := userlib.SymDec(FileKey, FileChunkEnc)
	err = json.Unmarshal(FileChunkDec, &FileChunk)

	//Iterate over file chunks to randomise their addresses
	Next := FileChunk.Next
	NewFileAddress := uuid.New()
	CurrentFP.FileAddress = NewFileAddress

	for Next != uuid.Nil {
		NewFileAddress2 := uuid.New()
		OldFileAddress := FileChunk.Next
		FileChunk.Next = NewFileAddress2
		FileChunkBytes, err := json.Marshal(FileChunk)
		if err != nil {
			return errors.New("An error occurred while marshalling file chunk.")
		}
		IV := userlib.RandomBytes(16)
		FileChunkEnc := userlib.SymEnc(FileKey, IV, FileChunkBytes)
		HMAC, err := userlib.HMACEval(FileKey, FileChunkEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for File chunk")
		}
		FileChunkEncMAC := append(FileChunkEnc, HMAC...)
		userlib.DatastoreSet(NewFileAddress, FileChunkEncMAC)
		NewFileAddress = NewFileAddress2
		//get next file chunk data
		NextFileEncMAC, ok := userlib.DatastoreGet(OldFileAddress)
		if !ok {
			return errors.New("An error occurred while retrieving next file chunk.")
		}
		HMAC = NextFileEncMAC[len(NextFileEncMAC)-64:]
		NextFileEnc := NextFileEncMAC[:len(NextFileEncMAC)-64]
		MACverify, err := userlib.HMACEval(FileKey, NextFileEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC verification for next file chunk.")
		}
		equal = userlib.HMACEqual(HMAC, MACverify)
		if equal != true {
			return errors.New("Verification test failed for next file chunk.")
		}
		NextFileDec := userlib.SymDec(FileKey, NextFileEnc)
		//Replace FileChunk ptr value with next file chunk data
		err = json.Unmarshal(NextFileDec, &FileChunk)
		Next = FileChunk.Next
		if Next == uuid.Nil {
			FinalChunkUUID := NewFileAddress2
			FinalChunkBytes, err := json.Marshal(FileChunk)
			if err != nil {
				return errors.New("An error occurred while marshalling Final File Chunk.")
			}
			IV = userlib.RandomBytes(16)
			FinalChunkEnc := userlib.SymEnc(FileKey, IV, FinalChunkBytes)
			HMAC, err = userlib.HMACEval(FileKey, FinalChunkEnc)
			if err != nil {
				return errors.New("An error occurred while generating HMAC for Final File Chunk.")
			}
			FinalChunkEncMAC := append(FinalChunkEnc, HMAC...)
			userlib.DatastoreSet(FinalChunkUUID, FinalChunkEncMAC)
		}
	}

	CurrentFPbytes, err := json.Marshal(CurrentFP)
	if err != nil {
		return errors.New("An error occurred while marshalling New Caller file pointer data.")
	}
	IV = userlib.RandomBytes(16)
	CurrentFPEnc := userlib.SymEnc(FileKey, IV, CurrentFPbytes)
	NewHmac, err := userlib.HMACEval(FileKey, CurrentFPEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for new Caller File pointer data")
	}
	CurrentFPEncMAC := append(CurrentFPEnc, NewHmac...)
	userlib.DatastoreSet(NewCallerFPUUID, CurrentFPEncMAC)

	return nil
}
