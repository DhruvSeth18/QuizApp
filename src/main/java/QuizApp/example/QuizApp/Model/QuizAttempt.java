package QuizApp.example.QuizApp.Model;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import QuizApp.example.QuizApp.Model.PassOrFail;
import org.springframework.data.annotation.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class QuizAttempt {
    @Id
    private String id;
    private String userId;
    private String quizId;
    private Double duration;                 // hours
    private int numberOfQuestion;
    private int marksObtained;
    private Double percentage;
    private PassOrFail passOrFail = PassOrFail.NOT_SUBMITTED;
    private List<QuestionAttempt> attemptedQuestions = new ArrayList<>();
    private LocalDateTime attemptedAt = LocalDateTime.now();
    private LocalDateTime submittedAt;
    private LocalDateTime quizStartTime;
    private int totalDisturbance;
    private Boolean endQuiz;
    private String result;
    private String status;
    private LocalTime startTime;
    private LocalTime endTime;
    private List<Questions> shuffledQuestions = new ArrayList<>();
}
