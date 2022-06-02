package controller;

import java.io.File;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import model.FileEncrypterDecrypter;

public class MainMenuController {
	
	public final static String SALT = "1234";
	public final static int ITERATIONS = 10000;
	public final static int KEY_LENGTH = 128;
	
	private FileEncrypterDecrypter fileED;
	private File inputEncryptedFile;
	private File inputDecryptedFile;
	private File inputHashFile;

    @FXML
    private PasswordField decriptPassword_txt;

    @FXML
    private PasswordField encriptPassword_txt;

    @FXML
    private TextField fileHash_txt;

    @FXML
    private TextField pathFileToDecript_txt;

    @FXML
    private TextField pathFileToEncript_txt;



    @FXML
    void initialize() {
    	this.fileED = new FileEncrypterDecrypter();
    }



    @FXML
    void decriptFileClicked(ActionEvent event) {
    	
    	if(validateEmptyFields(this.decriptPassword_txt)) {
    		
    		showErrorAlert("You should complete all the fields to decrypt a file");
    		
    	}else {
    		if(this.inputDecryptedFile != null && this.inputHashFile != null) {
        		
        		char[] password = this.decriptPassword_txt.getText().toCharArray();
        		
        		try {
    				String path = this.inputDecryptedFile.getAbsolutePath();
    				path = path.substring(0, path.length() - 4);
    				File outDec = new File(path);
    				
    				byte[] key = this.fileED.PBKDF2(password, SALT.getBytes(), ITERATIONS, KEY_LENGTH);
    				
    				this.fileED.decryptFile(key, this.inputDecryptedFile, outDec);
    				
    				if(this.fileED.verifySHA1(outDec, this.inputHashFile)) {
    					showInfoAlert("Your file has been decrypted becauses the hashes are the same.");
    					clearFields();
    					
    				} else {
    					showInfoAlert("The hashes are not the same, therefore your file could have been modified.");
    					clearFields();
    				}

    				
    			} catch (Exception e1) {
    				e1.printStackTrace();
    				showErrorAlert("The password doesn't match");
    			}
        		
    		}else {
    			
    			showErrorAlert("You should choose a file and its respective hash to decrypt it.");
    		}
    	}
    }

    
    @FXML
    void encriptFileClicked(ActionEvent event) {
    	
    	if(validateEmptyFields(this.encriptPassword_txt)) {
    		
    		showErrorAlert("You should complete all the fields to encrypt a file");
    		
    	}else {
    		if(inputEncryptedFile != null) {
        		char[] password = this.encriptPassword_txt.getText().toCharArray();
        		
    			try {
    				byte[] key = fileED.PBKDF2(password, SALT.getBytes(), ITERATIONS, KEY_LENGTH);
    				File outEnc = new File(inputEncryptedFile.getAbsolutePath()+".cif");
    				File outHash = new File(inputEncryptedFile.getAbsolutePath()+".hash");
       				this.fileED.encryptFile(key, this.inputEncryptedFile, outEnc);
    				this.fileED.generateSHA1(this.inputEncryptedFile, outHash);

    				showInfoAlert("The file has been ecrypted successfully.");
    				clearFields();
    				
    			} catch (Exception e1) {
    				e1.printStackTrace();
    			}
    			
    		}else {
    			showErrorAlert("You should choose a file to encrypt.");
    		}
    	}
    	
    }

    
    @FXML
    void fileHashClicked(ActionEvent event) {
    	FileChooser fileChooser = new FileChooser();
    	fileChooser.setTitle("Search a file hash to encrypt.");
    	
    	fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All FILES", "*.*"),
                new FileChooser.ExtensionFilter("HASH", "*.hash")
        );
    	
    	File file = fileChooser.showOpenDialog(null);
    	
    	if(file != null) {
    		this.inputHashFile = file;
    		this.fileHash_txt.setText(file.getPath());
    	}
    }

    
    @FXML
    void fileToDecriptClicked(ActionEvent event) {
    	FileChooser fileChooser = new FileChooser();
    	fileChooser.setTitle("Search a file to decrypt.");
    	
    	fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All FILES", "*.*"),
                new FileChooser.ExtensionFilter("CIF", "*.cif")
        );
    	
    	File file = fileChooser.showOpenDialog(null);
    	
    	if(file != null) {
    		this.inputDecryptedFile = file;
    		this.pathFileToDecript_txt.setText(file.getPath());
    	}
    }
    

    @FXML
    void fileToEncriptClicked(ActionEvent event) {
    	FileChooser fileChooser = new FileChooser();
    	fileChooser.setTitle("Search a file to encrypt");
    	
    	fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All Images", "*.*")
        );
    	
    	File file = fileChooser.showOpenDialog(null);
    	
    	if(file != null) {
    		this.inputEncryptedFile = file;
    		this.pathFileToEncript_txt.setText(file.getPath());
    	}
    }
    
    
    
    private void showErrorAlert(String message) {
    	
    	Alert alert = new Alert(Alert.AlertType.ERROR);
    	alert.setHeaderText(null);
        alert.setTitle("Error");
        alert.setContentText(message);
        alert.showAndWait();
    }
    
    
    private void showInfoAlert(String message) {
    	
    	Alert alert = new Alert(Alert.AlertType.INFORMATION);
    	alert.setHeaderText(null);
        alert.setTitle("Error");
        alert.setContentText(message);
        alert.showAndWait();
    }
    
    
    private boolean validateEmptyFields(PasswordField field) {
    	return field.getText() == null || field.getText().compareTo("") == 0;
    }
    
    
    private void clearFields() {
    	this.decriptPassword_txt.setText("");
    	this.encriptPassword_txt.setText("");
    	this.pathFileToDecript_txt.setText("");
    	this.pathFileToEncript_txt.setText("");
    	this.fileHash_txt.setText("");
    	
    	this.inputDecryptedFile = null;
    	this.inputEncryptedFile = null;
    	this.inputHashFile = null;
    }
}
