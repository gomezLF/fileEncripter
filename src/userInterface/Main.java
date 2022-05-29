package userInterface;
	
import controller.MainMenuController;
import javafx.application.Application;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.fxml.FXMLLoader;


public class Main extends Application {
	@Override
	public void start(Stage stage) {
		try {
			FXMLLoader loader = new FXMLLoader(getClass().getResource("MainMenu.fxml"));

	        MainMenuController mainMenuController = new MainMenuController();
	        loader.setController(mainMenuController);
	        Parent root = loader.load();

	        stage.setScene(new Scene(root));
	        stage.setTitle("Menu principal");
	        stage.setResizable(false);
	        stage.show();
	        
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		launch(args);
	}
}
