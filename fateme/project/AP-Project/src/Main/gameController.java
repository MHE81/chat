package Main;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;
import java.io.IOException;


public class gameController extends GameScene{

    @FXML
    private Button newGame;

    @FXML
    private Button joinGame;

    @FXML
    private Button exitBttn;

    @FXML
    public void newGameButtonPushed(ActionEvent event) throws IOException {
        client.writer.writeUTF("1");
        System.out.println("New Game Button Pushed.");
        Parent newGameParent = FXMLLoader.load(getClass().getResource("NewGame.fxml"));
        
        Scene newGameScene = new Scene(newGameParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node)event.getSource()).getScene().getWindow();
        window.setScene(newGameScene);
        window.show();
    }
    @FXML
    public void joinGameButtonPushed(ActionEvent event) throws IOException {
        client.writer.writeUTF("2");
        System.out.println("Join Game Button Pushed.");
        Parent joinGameParent = FXMLLoader.load(getClass().getResource("GuestClientInfo.fxml"));

        Scene joinGameScene = new Scene(joinGameParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
        window.setScene(joinGameScene);
        window.show();
    }
    @FXML
    protected void onExitButtonClick() throws IOException{
        client.writer.writeUTF("3");
        System.out.println("Exit Button Pushed.");
        System.exit(1);
    }
}
