package Main;

import javafx.fxml.FXML;
import javafx.scene.control.Label;

public class LastScene extends GameScene{

    @FXML
    private Label rate1Bttn;

    @FXML
    private Label rate2Bttn;

    @FXML
    private Label rate3Bttn;

    @FXML
    private Label name1Bttn;

    @FXML
    private Label name2Bttn;

    @FXML
    private Label name3Bttn;


    public void showAllRates(){
        Label[][] labels = new Label[3][2];
        labels[0][1] = rate1Bttn;
        labels[1][1] = rate2Bttn;
        labels[2][1] = rate3Bttn;
        labels[0][0] = name1Bttn;
        labels[1][0] = name2Bttn;
        labels[2][0] = name3Bttn;
        try {
            client.writer.writeUTF("Get All Rates");
            int size = Integer.parseInt(client.reader.readUTF());
            for(int i = 0; i < size; i++){
                    labels[i][0].setText(client.reader.readUTF());
            }
            for(int i = 0; i < size; i++){
                labels[i][1].setText(client.reader.readUTF());
            }
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }
    public void exitButtonPushed(){
        try {
            client.writer.writeUTF("3");
            System.out.println("Exit Button Pushed.");
            System.exit(1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
