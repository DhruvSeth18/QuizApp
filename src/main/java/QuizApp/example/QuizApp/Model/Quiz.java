    package QuizApp.example.QuizApp.Model;

    import java.time.LocalDateTime;
    import java.time.LocalTime;
    import java.util.List;

    import org.hibernate.validator.constraints.ru.INN;
    import org.springframework.data.annotation.Id;
    import org.springframework.data.mongodb.core.mapping.Document;

    import lombok.AllArgsConstructor;
    import lombok.Data;
    import lombok.NoArgsConstructor;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Document(collection = "Quiz")
    public class Quiz {
        @Id
        private String id;
        private String quizName;
        private double duration;
        private String description;
        private int totalQuestions;
        private int totalMarks;
        private int passingScore;
        private double passingPercentage;
        private boolean active;
        private List<Questions> questions;
        private List<String> attemptedUsersId;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        private String createdBy;
        private LocalDateTime quizDate;
        private LocalTime startTime;
        private LocalTime endTime;
    }
