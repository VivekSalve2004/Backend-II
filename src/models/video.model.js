import mongoose, {Schema} from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";


const videoSchema = new Schema(
    {
        videoFile: {
            type: String,  // cloudinary url
            required: [true , "Video File is Required field"],
        },

        thumbnail: {
            type: String,  // cloudinary url
            required: [true , "Video thumbnail is Required field"],
        },

        title: {
            type: String,  
            required: true
        }, 
        
        description: {
            type: String,  
            required: true
        },

        duration: {
            type: Number,       // cloudinary   
            required: true
        },

        views: {
            type: Number,
            default: 0,            
        },

        isPublished: {
            type: Boolean,
            default: true
        },

        owner: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },

    },
    {
        timestamps: true
    }
) 

// for complex aggregration queries 
videoSchema.plugin(mongooseAggregatePaginate)

export const Video = mongoose.model("Video" , videoSchema);