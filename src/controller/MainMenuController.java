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
	
	private FileEncrypterDecrypter modelo;
	private File inEnc;
	private File inDec;
	private File inHash;

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
    	this.modelo = new FileEncrypterDecrypter();
    }



    @FXML
    void decriptFileClicked(ActionEvent event) {
    	
    	if(validateEmptyFields(this.decriptPassword_txt)) {
    		showErrorAlert("Debe de llenar todos los campos anter de desencriptar un archivo");
    		
    	}else {
    		if(this.inDec != null && this.inHash != null) {
        		
        		char[] password = this.decriptPassword_txt.getText().toCharArray();
        		
        		try {
    				String path = this.inDec.getAbsolutePath();
    				path = path.substring(0, path.length() - 4);
    				File outDec = new File(path);
    				
    				byte[] key = this.modelo.PBKDF2(password, SALT.getBytes(), ITERATIONS, KEY_LENGTH);
    				
    				this.modelo.decrypt(key, this.inDec, outDec);
    				
    				if(this.modelo.verifySHA1(outDec, this.inHash)) {
    					showInfoAlert("Su archivo ha sido descifrado. Los hashes coinciden.");
    					clearFields();
    					
    				} else {
    					showInfoAlert("Su archivo ha sido descifrado, pero puede que haya sido manipulado. Los hashes no coinciden.");
    					clearFields();
    				}

    				
    			} catch (Exception e1) {
    				e1.printStackTrace();
    				showErrorAlert("La contrasena no concide");
    			}
        		
    		}else {
    			showErrorAlert("Debe de seleccionar un archivo y su correspondiente hash para desencriptarlo");
    		}
    	}
    }

    
    @FXML
    void encriptFileClicked(ActionEvent event) {
    	
    	if(validateEmptyFields(this.encriptPassword_txt)) {
    		
    		showErrorAlert("Debe de llenar todos los campos anter de encriptar un archivo");
    		
    	}else {
    		if(inEnc != null) {
        		char[] password = this.encriptPassword_txt.getText().toCharArray();
        		
    			try {
    				byte[] key = modelo.PBKDF2(password, SALT.getBytes(), ITERATIONS, KEY_LENGTH);
    				File outEnc = new File(inEnc.getAbsolutePath()+".cif");
    				File outHash = new File(inEnc.getAbsolutePath()+".hash");
    				
    				// Encrypt the file
    				this.modelo.encrypt(key, this.inEnc, outEnc);
    				
    				// Generate hash
    				this.modelo.generateSHA1(this.inEnc, outHash);

    				showInfoAlert("Se ha cifrado el archivo exitosamente");
    				clearFields();
    				
    			} catch (Exception e1) {
    				e1.printStackTrace();
    			}
    			
    		}else {
    			showErrorAlert("Debe de seleccionar un archivo para encriptarlo");
    		}
    	}
    	
    }

    
    @FXML
    void fileHashClicked(ActionEvent event) {
    	FileChooser fileChooser = new FileChooser();
    	fileChooser.setTitle("Buscar archivo a encriptar");
    	
    	fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All FILES", "*.*"),
                new FileChooser.ExtensionFilter("CIF", "*.cif"),
                new FileChooser.ExtensionFilter("HASH", "*.hash")
        );
    	
    	File file = fileChooser.showOpenDialog(null);
    	
    	if(file != null) {
    		this.inDec = file;
    		this.fileHash_txt.setText(file.getPath());
    	}
    }

    
    @FXML
    void fileToDecriptClicked(ActionEvent event) {
    	FileChooser fileChooser = new FileChooser();
    	fileChooser.setTitle("Buscar archivo a encriptar");
    	
    	fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All FILES", "*.*"),
                new FileChooser.ExtensionFilter("CIF", "*.cif")
        );
    	
    	File file = fileChooser.showOpenDialog(null);
    	
    	if(file != null) {
    		this.inDec = file;
    		this.pathFileToDecript_txt.setText(file.getPath());
    	}
    }
    

    @FXML
    void fileToEncriptClicked(ActionEvent event) {
    	FileChooser fileChooser = new FileChooser();
    	fileChooser.setTitle("Buscar archivo a encriptar");
    	
    	fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All Images", "*.*")
        );
    	
    	File file = fileChooser.showOpenDialog(null);
    	
    	if(file != null) {
    		this.inEnc = file;
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
    	
    	this.inDec = null;
    	this.inEnc = null;
    	this.inHash = null;
    }
}
