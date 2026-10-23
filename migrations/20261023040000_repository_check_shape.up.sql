ALTER TABLE repository_credentials ADD CONSTRAINT repository_check_shape CHECK (
    CASE WHEN check_command IS NULL THEN true
         WHEN array_ndims(check_command) = 1 THEN
             array_lower(check_command, 1) = 1
             AND cardinality(check_command) BETWEEN 1 AND 64
             AND array_position(check_command, NULL) IS NULL
             AND check_command[1] <> ''
         ELSE false
    END
);
