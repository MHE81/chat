package Main;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ToggleGroup;
import javafx.stage.Stage;

import java.io.IOException;

public class GameInfo extends GameScene{

    @FXML
    private RadioButton numberRB1;

    @FXML
    private RadioButton numberRB2;

    @FXML
    private RadioButton playWithComputer;

    @FXML
    private RadioButton repeatRB1;

    @FXML
    private RadioButton repeatRB2;

    @FXML
    private RadioButton repeatRB3;

    @FXML
    private RadioButton timeBttn;

    @FXML
    private ToggleGroup number;

    @FXML
    private ToggleGroup repeat;

    @FXML
    private ToggleGroup kind;

    public void submitButtonPushed(ActionEvent event){
            try {
                client.writer.writeUTF("Number Of Clients");
                if(playWithComputer.isSelected())
                    client.writer.writeUTF("1");
                else if (numberRB1.isSelected())
                    client.writer.writeUTF("2");
                else if (numberRB2.isSelected())
                    client.writer.writeUTF("3");
                if(repeatRB1.isSelected())
                    client.gameRepeatNum = 2;
                else if(repeatRB2.isSelected())
                    client.gameRepeatNum = 3;
                else if(repeatRB3.isSelected())
                    client.gameRepeatNum = 5;
                client.writer.writeUTF(String.valueOf(client.gameRepeatNum));
                if(timeBttn.isSelected()) {
                    client.timeGame = true;
                    client.writer.writeUTF("Time");
                }
                else
                    client.writer.writeUTF("Normal");

                if(client.reader.readUTF().equals("Connect!")){
                    Parent hGameParent = FXMLLoader.load(getClass().getResource("gameDetails.fxml"));
                    Scene hGameScene = new Scene(hGameParent);
                    //this line gets the stage information
                    Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
                    window.setScene(hGameScene);
                    window.show();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
    }
}
