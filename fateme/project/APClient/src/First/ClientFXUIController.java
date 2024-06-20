package First;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;
import java.io.IOException;


public class ClientFXUIController {
    @FXML
    private GridPane firstPane;

    @FXML
    private Button newGame;

    @FXML
    private Button joinGame;

    @FXML
    private Button exitBttn;

    /*
     * when this method is called, it will change the scene to
     * a New Game example
     */
    @FXML
    public void newGameButtonPushed(ActionEvent event) throws IOException {
        Parent newGameParent = FXMLLoader.load(getClass().getResource("newGame.fxml"));
        Scene newGameScene = new Scene(newGameParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node)event.getSource()).getScene().getWindow();
        window.setScene(newGameScene);
        window.show();
    }
    @FXML
    protected void onExitButtonClick(){
        System.exit(0);
    }

}

